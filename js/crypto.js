/**
 * OG STAFF — Cryptographic Architecture Module
 * Implements real RSA digital signatures using the W3C Web Crypto API.
 * 
 * Algorithm: RSASSA-PKCS1-v1_5
 * Key Size: 2048 bits
 * Public Exponent: 65537 (0x010001)
 * Hash Algorithm: SHA-256
 * Signature Length: 256 bytes (344 Base64 chars)
 */

export const CRYPTO_CONFIG = {
  algorithm: 'RSASSA-PKCS1-v1_5',
  modulusLength: 2048,
  publicExponent: new Uint8Array([1, 0, 1]), // 65537
  hash: 'SHA-256',
};

/**
 * ArrayBuffer to Base64 string converter
 * @param {ArrayBuffer} buffer
 * @returns {string}
 */
export function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * Base64 string to ArrayBuffer converter
 * @param {string} base64
 * @returns {ArrayBuffer}
 */
export function base64ToArrayBuffer(base64) {
  const clean = base64.replace(/\s+/g, '');
  const binary = atob(clean);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

/**
 * ArrayBuffer to Hexadecimal string converter
 * @param {ArrayBuffer} buffer
 * @returns {string}
 */
export function arrayBufferToHex(buffer) {
  const byteArray = new Uint8Array(buffer);
  return Array.from(byteArray)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Returns subtle crypto instance from window or globalThis
 */
function getSubtleCrypto() {
  const cryptoObj = typeof window !== 'undefined' ? window.crypto : globalThis.crypto;
  if (!cryptoObj || !cryptoObj.subtle) {
    throw new Error('Web Crypto API is not available. Please ensure you are serving this over localhost or HTTPS.');
  }
  return cryptoObj.subtle;
}

/**
 * Generates an RSA-2048 key pair suitable for RSASSA-PKCS1-v1_5 signing with SHA-256
 * @returns {Promise<CryptoKeyPair>}
 */
export async function generateKeyPair() {
  const subtle = getSubtleCrypto();
  try {
    const keyPair = await subtle.generateKey(
      {
        name: CRYPTO_CONFIG.algorithm,
        modulusLength: CRYPTO_CONFIG.modulusLength,
        publicExponent: CRYPTO_CONFIG.publicExponent,
        hash: { name: CRYPTO_CONFIG.hash }
      },
      true, // extractable for demo export & storage
      ['sign', 'verify']
    );
    return keyPair;
  } catch (err) {
    throw new Error(`Key pair generation failed: ${err.message}`);
  }
}

/**
 * Computes public key fingerprint:
 * 1. Exports public key as SPKI (SubjectPublicKeyInfo)
 * 2. SHA-256 hashes the SPKI bytes
 * 3. Returns the first 16 hexadecimal characters formatted with colons
 * @param {CryptoKey} publicKey
 * @returns {Promise<{short: string, full: string}>}
 */
export async function fingerprint(publicKey) {
  try {
    const subtle = getSubtleCrypto();
    const spki = await subtle.exportKey('spki', publicKey);
    const digest = await subtle.digest('SHA-256', spki);
    const fullHex = arrayBufferToHex(digest).toUpperCase();
    const shortRaw = fullHex.substring(0, 16);
    // Format as 8 pairs: XX:XX:XX:XX:XX:XX:XX:XX
    const formattedShort = shortRaw.match(/.{1,2}/g)?.join(':') || shortRaw;
    return {
      short: formattedShort,
      full: fullHex
    };
  } catch (err) {
    throw new Error(`Failed to compute public key fingerprint: ${err.message}`);
  }
}

/**
 * Exports a public key in either JWK (JSON Web Key) or SPKI (Base64) format
 * @param {CryptoKey} publicKey
 * @param {'jwk'|'spki'} format
 * @returns {Promise<JsonWebKey|string>}
 */
export async function exportPublicKey(publicKey, format = 'jwk') {
  const subtle = getSubtleCrypto();
  if (format === 'jwk') {
    return await subtle.exportKey('jwk', publicKey);
  } else if (format === 'spki') {
    const buffer = await subtle.exportKey('spki', publicKey);
    return arrayBufferToBase64(buffer);
  }
  throw new Error(`Unsupported export format: ${format}`);
}

/**
 * Exports a private key in JWK format
 * @param {CryptoKey} privateKey
 * @returns {Promise<JsonWebKey>}
 */
export async function exportPrivateKey(privateKey) {
  const subtle = getSubtleCrypto();
  return await subtle.exportKey('jwk', privateKey);
}

/**
 * Imports a public key from JWK object/string or Base64 SPKI
 * @param {object|string} data
 * @returns {Promise<CryptoKey>}
 */
export async function importPublicKey(data) {
  let parsed = data;
  if (typeof data === 'string') {
    const trimmed = data.trim();
    if (trimmed.startsWith('{')) {
      try {
        parsed = JSON.parse(trimmed);
      } catch (e) {
        throw new Error('Invalid JSON format for public JWK key.');
      }
    } else {
      // Assume Base64 SPKI
      try {
        const subtle = getSubtleCrypto();
        const buffer = base64ToArrayBuffer(trimmed);
        return await subtle.importKey(
          'spki',
          buffer,
          {
            name: CRYPTO_CONFIG.algorithm,
            hash: { name: CRYPTO_CONFIG.hash }
          },
          true,
          ['verify']
        );
      } catch (err) {
        throw new Error(`Failed to import SPKI public key: ${err.message}`);
      }
    }
  }

  // JWK validation
  if (parsed && typeof parsed === 'object') {
    if (parsed.kty !== 'RSA') {
      throw new Error(`Invalid key type '${parsed.kty}'. Expected 'RSA'.`);
    }
    // Set appropriate algorithm if omitted or verify it
    const jwk = {
      ...parsed,
      alg: parsed.alg || 'RS256',
      key_ops: ['verify']
    };
    try {
      const subtle = getSubtleCrypto();
      return await subtle.importKey(
        'jwk',
        jwk,
        {
          name: CRYPTO_CONFIG.algorithm,
          hash: { name: CRYPTO_CONFIG.hash }
        },
        true,
        ['verify']
      );
    } catch (err) {
      throw new Error(`Failed to import JWK public key: ${err.message}`);
    }
  }

  throw new Error('Unrecognized public key format. Provide JWK JSON or Base64 SPKI.');
}

/**
 * Imports a private key from JWK object or JSON string
 * @param {object|string} data
 * @returns {Promise<CryptoKey>}
 */
export async function importPrivateKey(data) {
  let parsed = data;
  if (typeof data === 'string') {
    try {
      parsed = JSON.parse(data.trim());
    } catch (e) {
      throw new Error('Invalid JSON format for private JWK key.');
    }
  }

  if (parsed && typeof parsed === 'object') {
    if (parsed.kty !== 'RSA') {
      throw new Error(`Invalid key type '${parsed.kty}'. Expected 'RSA'.`);
    }
    if (!parsed.d || !parsed.p || !parsed.q) {
      throw new Error('Supplied JWK is missing RSA private parameters (d, p, q).');
    }
    const jwk = {
      ...parsed,
      alg: parsed.alg || 'RS256',
      key_ops: ['sign']
    };
    try {
      const subtle = getSubtleCrypto();
      return await subtle.importKey(
        'jwk',
        jwk,
        {
          name: CRYPTO_CONFIG.algorithm,
          hash: { name: CRYPTO_CONFIG.hash }
        },
        true,
        ['sign']
      );
    } catch (err) {
      throw new Error(`Failed to import JWK private key: ${err.message}`);
    }
  }

  throw new Error('Unrecognized private key format. Provide a valid JWK with RSA parameters.');
}

/**
 * Derives the corresponding public key from a private JWK
 * @param {JsonWebKey} privateJwk
 * @returns {Promise<CryptoKey>}
 */
export async function derivePublicKeyFromPrivateJwk(privateJwk) {
  if (!privateJwk || !privateJwk.n || !privateJwk.e) {
    throw new Error('Private JWK must contain RSA modulus (n) and public exponent (e).');
  }
  const publicJwk = {
    kty: 'RSA',
    n: privateJwk.n,
    e: privateJwk.e,
    alg: 'RS256',
    ext: true,
    key_ops: ['verify']
  };
  return await importPublicKey(publicJwk);
}

/**
 * Canonicalizes staff data according to Section 3.2 rules.
 * Exactly these fields in exactly this order:
 * 1. staffId
 * 2. staffName
 * 3. department
 * 4. designation
 * 5. institution
 * 6. joiningDate
 * 7. validUntil
 * 
 * Excludes photo, barcode, and UI metadata.
 * Does NOT normalize or silently alter user input values.
 * 
 * @param {object} staff
 * @returns {string} UTF-8 canonical JSON string
 */
export function canonicalize(staff) {
  if (!staff || typeof staff !== 'object') {
    throw new Error('Staff data must be a valid object');
  }

  const requiredFields = [
    'staffId',
    'staffName',
    'department',
    'designation',
    'institution',
    'joiningDate',
    'validUntil'
  ];

  for (const field of requiredFields) {
    if (staff[field] === undefined || staff[field] === null) {
      throw new Error(`Missing required canonical field: '${field}'`);
    }
  }

  // Construct explicit object with strict key ordering
  const canonicalObj = {
    staffId: String(staff.staffId),
    staffName: String(staff.staffName),
    department: String(staff.department),
    designation: String(staff.designation),
    institution: String(staff.institution),
    joiningDate: String(staff.joiningDate),
    validUntil: String(staff.validUntil)
  };

  return JSON.stringify(canonicalObj);
}

/**
 * Signs a staff record using RSASSA-PKCS1-v1_5 and SHA-256
 * @param {CryptoKey} privateKey
 * @param {object} staff
 * @returns {Promise<string>} Base64-encoded signature (256 bytes / ~344 characters)
 */
export async function signStaff(privateKey, staff) {
  if (!privateKey) {
    throw new Error('Private key is required to sign staff record.');
  }

  try {
    const canonicalJson = canonicalize(staff);
    const encoder = new TextEncoder();
    const dataBytes = encoder.encode(canonicalJson);

    const subtle = getSubtleCrypto();
    const signatureBuffer = await subtle.sign(
      { name: CRYPTO_CONFIG.algorithm },
      privateKey,
      dataBytes
    );

    return arrayBufferToBase64(signatureBuffer);
  } catch (err) {
    throw new Error(`Digital signing failed: ${err.message}`);
  }
}

/**
 * Verifies staff record digital signature
 * @param {CryptoKey} publicKey
 * @param {object} staff
 * @param {string} signatureB64
 * @returns {Promise<boolean>} True if signature matches canonical staff data exactly
 */
export async function verifyStaff(publicKey, staff, signatureB64) {
  if (!publicKey) {
    throw new Error('Public key is required to verify staff signature.');
  }
  if (!signatureB64 || typeof signatureB64 !== 'string') {
    throw new Error('A valid Base64 signature string is required.');
  }

  try {
    const canonicalJson = canonicalize(staff);
    const encoder = new TextEncoder();
    const dataBytes = encoder.encode(canonicalJson);
    const signatureBuffer = base64ToArrayBuffer(signatureB64);

    // RSA-2048 signature must be exactly 256 bytes
    if (signatureBuffer.byteLength !== 256) {
      return false;
    }

    const subtle = getSubtleCrypto();
    const isValid = await subtle.verify(
      { name: CRYPTO_CONFIG.algorithm },
      publicKey,
      signatureBuffer,
      dataBytes
    );

    return isValid;
  } catch (err) {
    // Malformed base64, incorrect padding, or cryptographic mismatch
    return false;
  }
}

/**
 * Calculates SHA-256 digest of arbitrary string (used for educational verification logs)
 * @param {string} text
 * @returns {Promise<string>} Hexadecimal digest
 */
export async function calculateSha256Hex(text) {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const subtle = getSubtleCrypto();
  const digest = await subtle.digest('SHA-256', data);
  return arrayBufferToHex(digest);
}

/**
 * Triggers a browser download of a JSON object as a file
 * @param {string} filename
 * @param {object} object
 */
export function downloadJSON(filename, object) {
  const jsonStr = JSON.stringify(object, null, 2);
  const blob = new Blob([jsonStr], { type: 'application/json;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
