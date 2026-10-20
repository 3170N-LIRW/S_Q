# S_Q — Password and Message Utility

A small browser utility inspired by Asher and Eliezer. It generates random passwords and encrypts or decrypts UTF-8 text using the browser's Web Crypto API.

**This is an unaudited local utility, not a complete secure messaging service.** Using AES-GCM does not make the page, browser, device, hosting or key-sharing process trustworthy.

## Run it

Serve `index.html` over HTTPS, or use a loopback server for local development:

```sh
python3 -m http.server 8000 --bind 127.0.0.1
```

Open http://localhost:8000 in a browser supporting Web Crypto, TextEncoder and TextDecoder. The application checks for a secure context and the required APIs; it disables cryptographic actions when these are unavailable. Do not rely on opening the file with a `file://` URL. Clipboard access also depends on browser permissions and may require manual copying.

There is no build step, external JavaScript, external stylesheet, analytics or application network request. The delivered code performs cryptography locally and does not intentionally persist secrets to cookies, localStorage or IndexedDB. Loading the page still contacts its host. These properties cannot protect you if an attacker changes the delivered page or controls your browser.

## Password generation

1. Choose an integer length from 8 to 128 (default: 20).
2. Select at least one character type.
3. Select **Generate password**, then copy or save it in your password manager.

Random bytes come from `crypto.getRandomValues()`. Rejection sampling avoids bias when mapping bytes to the selected character pool. Whole candidates missing a selected character type are rejected, so each successful password contains every selected type. Generation stops with an error after 128 unsuccessful candidates.

The pools are ASCII uppercase letters, lowercase letters, digits and these symbols:

```text
!@#$%^&*()_+[]{}|;:',.<>?/
```

The eight-character minimum is an input limit, not a claim of adequate strength. Use long, unique passwords and comply with the destination site's requirements. Generated passwords are displayed visibly. This is not a password manager and offers no password recovery, storage or breach checking.

## Encrypt text

1. Select **Generate new key**, or paste a previously generated key.
2. Save the key separately, for example in a trusted password manager.
3. Enter your plaintext and select **Encrypt text**.
4. Copy the result. It contains the version, IV, ciphertext and authentication tag, **not the key**.

A key is 32 random bytes (256 bits), encoded as canonical standard Base64: 44 characters, ending in `=`. Arbitrary passwords and passphrases are not accepted. Base64 encodes bytes; it does not add entropy. The validator cannot tell whether an imported key was generated randomly. Do not Base64-encode a memorable phrase to make a key.

Key generation is explicit: an empty key field causes an error. Generating another key replaces the field; save the previous key first. Prefer a fresh key for each message. The imported CryptoKey is non-extractable, but the original Base64 key remains in the page and can be copied; this is not protection against malicious JavaScript.

Encryption uses AES-256-GCM with a fresh random 12-byte (96-bit) IV and a 128-bit authentication tag. An IV must never repeat with the same key. Random IVs make collisions unlikely at this utility's intended low volume, but do not guarantee uniqueness. There is no persistent per-key counter, usage limit or key-rotation system; do not use this page for high-volume encryption.

Only non-empty plaintext of at most 65,536 UTF-8 bytes is accepted. Multibyte characters count towards the byte limit. Whitespace, newlines, emoji and a leading Unicode byte-order mark are preserved. Invalid Unicode surrogate sequences are rejected.

## Decrypt text

Paste the matching Base64 key, paste the complete SQ1 result into the message field, and select **Decrypt text**.

Malformed input, unsupported versions, incorrect byte lengths and oversized messages are rejected before decryption. A wrong key or altered IV, ciphertext or tag produces a decryption error. No unauthenticated plaintext is displayed. Authenticated bytes that are not valid UTF-8 also produce an error.

The UI clears stale results before encryption/decryption and when their inputs change. Concurrent operations are disabled. Results are assigned to text-field values, never interpreted as HTML. Copy failures are reported with instructions for manual copying.

**The old CryptoJS passphrase format is incompatible.** There is no automatic fallback or migration. Keep any existing ciphertext and keys until you have verified a deliberate migration using a separately reviewed legacy reader. Legacy ciphertext does not gain authenticity merely by being re-encrypted.

## SQ1 format

The output is a single line:

```text
SQ1.<Base64 IV>.<Base64 ciphertext-and-tag>
```

| Item | Definition |
| --- | --- |
| Version | Literal `SQ1`; other versions are rejected |
| Cipher | AES-GCM with a 32-byte raw key |
| IV | 12 bytes; standard Base64; fresh for every encryption |
| Additional authenticated data | UTF-8 bytes of the exact string `S_Q|1|AES-256-GCM` |
| Ciphertext and tag | Web Crypto output: ciphertext followed by the 16-byte tag |
| Plaintext encoding | UTF-8 |
| Base64 | Standard alphabet, canonical padding, no internal whitespace; not Base64URL |
| Limits | 65,536 plaintext bytes; 65,552 ciphertext-and-tag bytes; 87,425 characters in a canonical envelope |

Leading and trailing whitespace on a pasted key or envelope is ignored. Internal whitespace is rejected. The raw envelope input allows up to 1,024 extra characters for surrounding whitespace, then applies the canonical envelope limit after trimming.

The version determines the algorithm and authenticated context; the application does not accept caller-selected algorithms, tag lengths or AAD. The IV and tag travel with the ciphertext and are not secrets. A separate MAC is not required for this AES-GCM format.

## What this change addresses

All application changes remain within `index.html`:

- Replace `Math.random()` with browser cryptographic randomness and unbiased character selection.
- Replace CryptoJS passphrase encryption with native AES-GCM and explicit random keys.
- Remove both the CryptoJS script CDN and Bootstrap stylesheet CDN.
- Validate key encodings, envelope version, sizes, password options and Unicode.
- Handle authentication failures, unavailable APIs, clipboard failures and asynchronous UI state.
- Keep keys separate from encrypted output and use cautious, accurate UI wording.
- Offer manual field clearing and best-effort clearing when the page is hidden by navigation.

## Limitations and work beyond this single-file change

| Area | Remaining work |
| --- | --- |
| Key sharing | There is no authenticated key exchange, recipient directory or identity verification. Share keys through a separately authenticated trusted channel; anyone obtaining both key and ciphertext can decrypt. |
| Sender identity | AES-GCM verifies possession of the shared key and detects modification. Every key holder can forge a valid message. It does not prove who sent it. |
| Messaging protocol | No replay detection, ordering, expiry, forward secrecy, post-compromise security, multi-device support or revocation. These require a reviewed protocol and broader state/key-management design. |
| Passphrases | A future passphrase mode needs a separately versioned format, random salts, a reviewed password KDF and calibrated parameters. Human passwords must never be used directly as AES keys. |
| Endpoint security | Malicious extensions, XSS, a compromised browser/device, screenshots or a changed hosted page can expose keys and plaintext. Changing the cipher cannot solve this. |
| Deployment | Enforce HTTPS; review hosting and repository access; deploy an appropriate Content Security Policy, framing restrictions and other response headers; review the release pipeline. These are deployment tasks, not necessarily a messaging redesign. |
| CSP | This version does not supply a CSP. A single-file page can use an exact inline-script hash; regenerate it whenever the script changes. Alternatively separate scripts/styles and deploy a restrictive header policy. A fixed nonce or permissive inline-script policy is not an equivalent safeguard. |
| Memory and clipboard | JavaScript cannot guarantee secure erasure. Clearing fields or zeroing temporary byte arrays does not erase strings, browser copies, clipboard history or synced clipboard data. |
| Metadata | Ciphertext reveals approximate plaintext length. There is no padding, traffic protection or sender/recipient metadata protection. |
| Assurance | Independent security review and real-browser testing remain necessary. Primitive selection alone is not an audit or a production-readiness guarantee. |

The existing Pages workflow is outside this patch's scope. A successful source change does not establish that the hosted page has been deployed correctly. Review the workflow and verify the delivered page before publishing it.

## Verification

Run the dependency-free regression tests with a current supported Node.js release:

```sh
node --test tests/crypto.test.cjs
```

The tests load the actual inline application script, use Node's Web Crypto for cryptographic checks, and stub the DOM. They cover Unicode round trips, wrong keys, modified IV/ciphertext/tag, format/size validation, random password bounds, rejection sampling and UI error paths. They do not replace browser testing.

Before deployment, also check in each supported browser:

- Encrypt/decrypt a message containing spaces, newlines and emoji. Re-encrypting with the same key should produce different envelopes.
- Change the key or an envelope byte. Confirm failure and an empty result field.
- Try an invalid Base64 key, a legacy CryptoJS string, an unsupported version, an empty message and an oversized UTF-8 message.
- Check password lengths 8 and 128, every character-type combination, no selected type and fractional lengths.
- Deny clipboard access and confirm the manual-copy message.
- Confirm unsupported/insecure contexts disable cryptographic actions.
- Verify keyboard operation, visible focus and status announcements.
- Check the network panel for unexpected third-party requests and confirm the hosted source matches the reviewed source.

## References

- [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
- [getRandomValues](https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues)
- [AES-GCM parameters](https://developer.mozilla.org/en-US/docs/Web/API/AesGcmParams)
- [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final)

## Licence

See [LICENSE](LICENSE).
