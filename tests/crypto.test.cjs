"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const { join } = require("node:path");
const vm = require("node:vm");
const { webcrypto } = require("node:crypto");
const { TextEncoder, TextDecoder } = require("node:util");

const html = readFileSync(join(__dirname, "..", "index.html"), "utf8");
const source = html.match(/<script>([\s\S]*?)<\/script>/)[1];

function harness(options = {}) {
    const nodes = new Map();
    for (const [, id] of html.matchAll(/\bid="([^"]+)"/g)) {
        nodes.set(id, {
            value: "", checked: false, disabled: false, type: "text",
            textContent: "", listeners: {},
            addEventListener(event, handler) { this.listeners[event] = handler; }
        });
    }
    const node = id => nodes.get(id);
    node("password-length").value = "20";
    for (const name of ["uppercase", "lowercase", "numbers", "symbols"]) node("include-" + name).checked = true;
    const context = vm.createContext({
        crypto: options.crypto || webcrypto,
        isSecureContext: options.secure !== false,
        TextEncoder, TextDecoder, Uint8Array,
        btoa: value => Buffer.from(value, "binary").toString("base64"),
        atob: value => Buffer.from(value, "base64").toString("binary"),
        navigator: { clipboard: options.clipboard },
        document: {
            getElementById: node,
            querySelectorAll: () => [...nodes.values()]
        },
        window: { addEventListener() {} }
    });
    vm.runInContext(source + "\n globalThis.api = { encryptText, decryptText, generateKeyText, " +
        "makePassword, encodeBase64, decodeBase64, encodeMessage, parsePayload, randomIndex };", context);
    return { api: context.api, node, context };
}

function alter(envelope, part, offset = 0) {
    const parts = envelope.split(".");
    const bytes = Buffer.from(parts[part], "base64");
    bytes[offset < 0 ? bytes.length + offset : offset] ^= 1;
    parts[part] = bytes.toString("base64");
    return parts.join(".");
}

test("uses native APIs, no legacy/CDN script or inline event attributes", () => {
    assert.doesNotMatch(html, /Math\.random|CryptoJS|<script[^>]+src=|<link[^>]+href=|\sonclick=/);
    assert.match(source, /getRandomValues/);
    assert.match(source, /tagLength: 128/);
});

test("Unicode, BOM, whitespace and HTML-looking text round-trip exactly", async () => {
    const { api } = harness();
    const key = api.generateKeyText();
    assert.equal(Buffer.from(key, "base64").length, 32);
    for (const message of ["hello", "  \n\t", "\uFEFFstart", "Shalom שלום 🌍\n", "<img src=x onerror=alert(1)>"]) {
        const encrypted = await api.encryptText(message, key);
        assert.equal(await api.decryptText(encrypted, key), message);
        assert.match(encrypted, /^SQ1\./);
        assert.equal(encrypted.includes(key), false);
    }
});

test("same key and plaintext get fresh IVs", async () => {
    const { api } = harness();
    const key = api.generateKeyText();
    const a = await api.encryptText("same", key);
    const b = await api.encryptText("same", key);
    assert.notEqual(a.split(".")[1], b.split(".")[1]);
});

test("wrong key, modified IV, ciphertext and tag fail authentication", async () => {
    const { api } = harness();
    const key = api.generateKeyText();
    const encrypted = await api.encryptText("authentication test", key);
    await assert.rejects(api.decryptText(encrypted, api.generateKeyText()), /Decryption failed/);
    for (const modified of [alter(encrypted, 1), alter(encrypted, 2), alter(encrypted, 2, -1)]) {
        await assert.rejects(api.decryptText(modified, key), /Decryption failed/);
    }
});

test("a ciphertext made with different AAD is rejected", async () => {
    const { api } = harness();
    const keyText = api.generateKeyText();
    const key = await webcrypto.subtle.importKey("raw", Buffer.from(keyText, "base64"), "AES-GCM", false, ["encrypt"]);
    const iv = webcrypto.getRandomValues(new Uint8Array(12));
    const encrypted = await webcrypto.subtle.encrypt({
        name: "AES-GCM", iv, additionalData: new TextEncoder().encode("other"), tagLength: 128
    }, key, new TextEncoder().encode("hello"));
    const envelope = "SQ1." + api.encodeBase64(iv) + "." + Buffer.from(encrypted).toString("base64");
    await assert.rejects(api.decryptText(envelope, keyText), /Decryption failed/);
});

test("authenticated non-UTF-8 plaintext is rejected", async () => {
    const { api } = harness();
    const keyText = api.generateKeyText();
    const key = await webcrypto.subtle.importKey("raw", Buffer.from(keyText, "base64"), "AES-GCM", false, ["encrypt"]);
    const iv = webcrypto.getRandomValues(new Uint8Array(12));
    const encrypted = await webcrypto.subtle.encrypt({
        name: "AES-GCM", iv, additionalData: new TextEncoder().encode("S_Q|1|AES-256-GCM"), tagLength: 128
    }, key, new Uint8Array([255]));
    await assert.rejects(api.decryptText("SQ1." + api.encodeBase64(iv) + "." +
        Buffer.from(encrypted).toString("base64"), keyText), /not valid UTF-8/);
});

test("Base64 size, alphabet, padding and pad bits are validated", () => {
    const { api } = harness();
    for (const invalid of ["", "A", "AA", "A===", "AA-_", "AA\n=", "AB==", "AA=A"]) {
        assert.throws(() => api.decodeBase64(invalid, 1, 32, "Test"), /Base64/);
    }
    assert.equal(api.decodeBase64("AA==", 1, 1, "Test")[0], 0);
    assert.throws(() => api.decodeBase64("AAAA", 1, 1, "Test"), /Base64/);
    assert.throws(() => api.decodeBase64("AA==", 2, 2, "Test"), /Base64/);
});

test("empty, oversized, malformed, truncated and legacy input is rejected", async () => {
    const { api } = harness();
    const key = api.generateKeyText();
    for (const value of ["", "U2FsdGVkX1+legacy", "SQ2.AAAA.AAAA", "SQ1.AAAA.AAAA",
        "SQ1." + "A".repeat(16) + "." + "A".repeat(20), "A".repeat(88450)]) {
        await assert.rejects(api.decryptText(value, key));
    }
    for (const value of ["", "a".repeat(65537), "🌍".repeat(16385), "\ud800", "\udc00"]) {
        await assert.rejects(api.encryptText(value, key));
    }
    for (const invalidKey of ["", "password", Buffer.alloc(16).toString("base64")]) {
        await assert.rejects(api.encryptText("hello", invalidKey), /Key/);
    }
});

test("maximum byte boundary and surrounding paste whitespace", async () => {
    const { api } = harness();
    const key = api.generateKeyText();
    const message = "🌍".repeat(16384);
    const encrypted = await api.encryptText(message, " \n" + key + "\t");
    assert.equal(encrypted.length, 87425);
    assert.equal(await api.decryptText(" \n" + encrypted + "\t", key), message);
});

test("all password group combinations at minimum and maximum lengths", () => {
    const { api } = harness();
    const names = ["uppercase", "lowercase", "numbers", "symbols"];
    const pools = ["ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz",
        "0123456789", "!@#$%^&*()_+[]{}|;:',.<>?/"];
    for (let mask = 1; mask < 16; mask++) {
        const selected = names.filter((_, index) => mask & (1 << index));
        const groups = pools.filter((_, index) => mask & (1 << index));
        for (const length of [8, 128]) {
            const password = api.makePassword(String(length), selected);
            assert.equal(password.length, length);
            assert.ok([...password].every(character => groups.join("").includes(character)));
            for (const group of groups) assert.ok([...password].some(character => group.includes(character)));
        }
    }
});

test("bad password options are rejected", () => {
    const { api } = harness();
    for (const value of ["", "7", "129", "8.5", "-8", "1e2", "Infinity", "NaN"]) {
        assert.throws(() => api.makePassword(value, ["uppercase"]), /length/);
    }
    for (const groups of [[], ["unknown"], ["uppercase", "uppercase"], ["toString"]]) {
        assert.throws(() => api.makePassword("20", groups), /character type/);
    }
});

test("rejection sampling discards the modulo-biased tail", () => {
    const samples = [255, 250, 249];
    const { api } = harness({ crypto: {
        subtle: {}, getRandomValues(array) { array[0] = samples.shift(); return array; }
    } });
    assert.equal(api.randomIndex(10), 9);
    assert.equal(samples.length, 0);
});

test("UI clears stale output on failure and reports clipboard denial", async () => {
    const { node } = harness({ clipboard: { writeText: async () => { throw new Error("denied"); } } });
    node("encryption-result").value = "stale plaintext";
    await node("decrypt").listeners.click();
    assert.equal(node("encryption-result").value, "");
    assert.equal(node("decrypt").disabled, false);
    node("password-result").value = "example";
    await node("copy-password").listeners.click();
    assert.match(node("status").textContent, /permission denied/);
});

test("UI does not copy placeholder text and handles unavailable clipboard", async () => {
    const { node } = harness();
    await node("copy-password").listeners.click();
    assert.match(node("status").textContent, /nothing to copy/);
    node("password-result").value = "example";
    await node("copy-password").listeners.click();
    assert.match(node("status").textContent, /Clipboard unavailable/);
});

test("changing options clears old passwords; clear resets key visibility", () => {
    const { node } = harness();
    node("password-result").value = "old";
    node("password-length").listeners.input();
    assert.equal(node("password-result").value, "");
    node("encryption-key").value = "secret";
    node("show-key").checked = true;
    node("show-key").listeners.change();
    assert.equal(node("encryption-key").type, "text");
    node("clear-all").listeners.click();
    assert.equal(node("encryption-key").value, "");
    assert.equal(node("encryption-key").type, "password");
});

test("unsupported/insecure contexts disable operations", () => {
    for (const options of [{ secure: false }, { crypto: {} }]) {
        const { node } = harness(options);
        assert.equal(node("encrypt").disabled, true);
        assert.equal(node("generate-password").disabled, true);
        assert.match(node("status").textContent, /Web Crypto is unavailable/);
    }
});
