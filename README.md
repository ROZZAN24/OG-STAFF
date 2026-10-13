# OG STAFF — Staff ID Card Generation & Verification System Using RSA Digital Signatures

An educational college mini-project for Security Laboratory demonstrations and viva examinations. Built with vanilla JavaScript, modern CSS, and the native **W3C Web Crypto API (`crypto.subtle`)**.

---

## 1. Project Objective & Overview

Traditional physical staff ID cards with printed text and standard barcodes are trivially forged or altered using desktop publishing tools. A malicious actor can easily change a staff member's designation, department, or expiration date. 

**OG STAFF** solves this problem by applying **asymmetric public-key cryptography (RSA-2048)** and **cryptographic hashing (SHA-256)**:
- Institutional authorities sign the canonical staff record using their **Private Key**.
- Verifiers (such as security staff, entrance gates, or auditing portals) verify the mathematical authenticity of the record using the institution's trusted **Public Key**.
- Any tampering with a single character in the staff record changes the SHA-256 hash completely (the *Avalanche Effect*) and causes signature verification to fail immediately.
- 1D linear **Code 128 barcodes** are generated and scanned via live camera or image upload to retrieve and cryptographically verify the digital staff credentials.

---

## 2. Technology Stack

- **Markup & Styling:** HTML5, CSS3 (Modern Cybersecurity Dark Theme), Google Fonts Inter.
- **Client Logic:** Vanilla JavaScript (ES6+ Modules, zero frameworks).
- **Cryptographic Operations:** W3C Web Crypto API (`window.crypto.subtle`) — hardware/OS-level native cryptographic engine.
- **Barcode Generation:** `JsBarcode` (Code 128 1D linear barcode rendering into scalable SVG).
- **Barcode Scanning:** `@zxing/library` (Zebra Crossing browser scanner supporting Code 128 live camera stream and static image decoding).
- **Data Persistence:** Browser `LocalStorage` (Demo cryptographic keys, signed payload storage, and recent history).
- **ID Card Export:** HTML5 Canvas high-resolution PNG rendering and dedicated CSS `@media print` print engine.

> **Strict Project Constraints Observed:**
> - Zero backend dependencies (no Node.js, Python, PHP, or external SQL/NoSQL databases).
> - Zero simulated or fake cryptographic calculations.
> - **Zero QR codes** used anywhere in the application (Code 128 1D linear barcodes only).

---

## 3. Project File Structure

```
OG-STAFF/
├── index.html                  # Landing page & architecture overview
├── generate.html               # Key management, staff form, RSA signing, printable card
├── verify.html                 # Trusted public key management, live camera scanning, verification
├── demo.html                   # Interactive 3-step security lab tampering & attacker demo
├── about.html                  # Cryptographic theory, comparison table, limitations, viva Q&A
├── README.md                   # Complete documentation, running instructions & test checklist
├── css/
│   └── style.css              # Cyber-themed styling, animations, toasts & print styles
├── js/
│   ├── crypto.js               # Web Crypto RSA-2048, SHA-256, signing, verification & fingerprints
│   ├── generate.js             # Generation UI, form validation, JsBarcode, PNG export
│   ├── verify.js               # Verification UI, ZXing camera scanner, audit logging
│   ├── demo.js                 # Tampering demonstration, avalanche effect & attacker simulation
│   └── common.js               # LocalStorage, date expiration logic, toasts & token helpers
└── assets/
    └── placeholder-avatar.svg  # Default avatar SVG graphic
```

---

## 4. How to Run the Application Locally

Modern web browsers mandate a **Secure Context** (HTTPS or `http://localhost`) for the Web Crypto API (`window.crypto.subtle`) and device camera access (`navigator.mediaDevices.getUserMedia`). Therefore, the application must be served over `localhost`.

### Step 1: Clone or Navigate to the Directory
Open your terminal / PowerShell in the project directory:
```bash
cd "d:\OG Staff"
```

### Step 2: Start a Local HTTP Server
Using Python (built into standard installations):
```bash
python -m http.server 8080
```
*(Or in Python 2: `python -m SimpleHTTPServer 8080`)*

### Step 3: Open in Browser
Open your browser and navigate to:
```
http://localhost:8080/index.html
```

---

## 5. Cryptographic Architecture

### 5.1 RSA Configuration
- **Algorithm:** `RSASSA-PKCS1-v1_5`
- **Modulus Length:** 2048 bits
- **Public Exponent ($e$):** 65537 (`0x010001` or `new Uint8Array([1, 0, 1])`)
- **Hash Algorithm:** SHA-256 (produces a 32-byte digest)
- **Signature Length:** 256 bytes (represented as approximately 344 Base64 characters)

### 5.2 Canonical Data Structure
To prevent differences in JavaScript object serialization from producing mismatched hashes, `canonicalize(staff)` in `js/crypto.js` constructs an explicitly ordered object:
```json
{
  "staffId": "STF-2026-881",
  "staffName": "Dr. Priya Sharma",
  "department": "Cybersecurity & Networks",
  "designation": "Associate Professor",
  "institution": "Apex Institute of Technology",
  "joiningDate": "2025-06-01",
  "validUntil": "2028-06-01"
}
```
**Canonicalization Rules:**
1. Fields must match exactly in that order.
2. The payload is converted to UTF-8 bytes using `new TextEncoder().encode()`.
3. The photograph is display-only and is **excluded** from the canonical signed payload.
4. Barcode images, UI timestamps, and styling metadata are excluded.

### 5.3 Public Key Fingerprint
A 16-character hexadecimal fingerprint is generated to uniquely identify public keys:
1. Export public key in standard SPKI (`SubjectPublicKeyInfo`) format.
2. Hash SPKI bytes using `crypto.subtle.digest("SHA-256", spkiBytes)`.
3. Take the first 16 hex characters formatted as `XX:XX:XX:XX:XX:XX:XX:XX`.

---

## 6. Code 128 Barcode Strategy

Code 128 is a 1D linear barcode. Encoding a full JSON payload plus a 344-character Base64 signature would require over 500 characters, producing an impractically wide barcode that cannot physically fit on a standard 85.6mm &times; 54mm ID badge.

**Solution:**
1. The badge prints a compact, unique record token: `OG-STF-XXXX`.
2. The full signed record is saved locally in browser LocalStorage under that token.
3. Users can also export the full signed record as a `.json` file for offline verification on other devices.
4. Scanning the barcode decodes the token, loads the signed record, and verifies the RSA signature using the verifier's trusted public key.

---

## 7. Independent Expiration Policy

Signature validity and temporal expiration are evaluated independently:
- **`VERIFIED`:** Signature matches trusted public key AND current date is before or on `validUntil`.
- **`EXPIRED`:** Signature is authentic and valid, but the current date has passed `validUntil`.
- **`INVALID`:** Signature fails verification (tampered data, incorrect key, or forgery).
- **`ERROR`:** Malformed payload, record missing, or missing trusted public key.

> *Security Rule:* An expired record that has also been altered will fail cryptographic verification and will be reported as **`INVALID`**, never `EXPIRED`.

---

## 8. Test Cases & Verification Checklist

| Test # | Description | Steps | Expected Result | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Test 1** | Valid Record Verification | Generate key pair, sign new staff record, verify with matching public key. | Status: `VERIFIED` (Signature Valid) | **PASS** |
| **Test 2** | Tampered Data Detection | Change 1 field (e.g. designation to "Professor"), verify with original signature. | Status: `INVALID` (Signature Mismatch) | **PASS** |
| **Test 3** | Attacker Key Forgery | Sign record with Attacker private key; verify with Issuer public key. | Status: `INVALID` (Forged signature rejected) | **PASS** |
| **Test 4** | Expired Record Verification | Create a record with a past `validUntil` date; sign and verify. | Status: `EXPIRED` (Signature Valid, Expired) | **PASS** |
| **Test 5** | Modified Signature | Change 1 character in Base64 signature string; verify. | Status: `INVALID` | **PASS** |
| **Test 6** | Unrelated Public Key | Verify genuine record using an unrelated RSA public key. | Status: `INVALID` | **PASS** |
| **Test 7** | Barcode Token Scanning | Scan Code 128 barcode using camera or uploaded image. | Decodes token, loads payload, verifies signature. | **PASS** |
| **Test 8** | Unknown Token Handling | Scan a valid token not present in LocalStorage. | Displays "Record not found on this device". | **PASS** |
| **Test 9** | Public Key Export / Import | Export public JWK file; re-import in Verifier; verify record. | Status: `VERIFIED` | **PASS** |
| **Test 10** | Malformed JSON / Input | Submit malformed JSON or empty strings in manual verification. | Clear error toast / validation error displayed. | **PASS** |
| **Test 11** | Expired + Tampered Record | Modify signed field in an expired record. | Status: `INVALID` (Tampering takes precedence). | **PASS** |
| **Test 12** | Photo Modification | Change staff photo while leaving signed fields untouched. | Signature remains valid (photo is unsigned). | **PASS** |

---

## 9. Security Warnings & Real-World Limitations

1. **LocalStorage Key Storage:** For this educational laboratory demonstration, demo keys are persisted in browser `LocalStorage`. LocalStorage is unencrypted and accessible to scripts on the origin. In production, institutional private keys must reside inside a **Hardware Security Module (HSM)** or secure cloud KMS (e.g. AWS KMS, GCP Cloud KMS, HashiCorp Vault).
2. **Public Key Trust Model:** A public key only verifies that data was signed by the matching private key; it does not prove institutional authority on its own. Public keys must be distributed via an institutional Public Key Infrastructure (PKI) with a trusted Root Certificate Authority (CA).
3. **Revocation Service:** This standalone client cannot check real-time employee revocation lists (OCSP / CRL).
4. **Barcode Duplication:** 1D barcodes can be photocopied. True anti-cloning in production requires cryptographic smart cards (NFC chip with challenge-response) or holographic watermarks.

---

## 10. Viva Preparation Notes

1. **Why RSASSA-PKCS1-v1_5 instead of raw RSA?** Raw RSA is vulnerable to mathematical homomorphic attacks. PKCS#1 v1.5 adds deterministic padding and an ASN.1 `DigestInfo` prefix identifying the hash function.
2. **Why canonicalize JSON?** JSON properties have arbitrary order in memory. Different parsers format spaces differently. Canonicalization ensures the identical byte sequence is hashed every time.
3. **Why does changing 1 character invalidate the signature?** The SHA-256 hash changes radically due to the avalanche effect. The verifier decrypts the signature with the public key to retrieve the original hash; because the hashes do not match, verification fails.
4. **Is a digital signature encryption?** No. Encryption hides content. A digital signature leaves content plain and human-readable while mathematically guaranteeing authenticity and integrity.

---

*OG STAFF &bull; Educational Security Laboratory Project &bull; Department of Information Security*
