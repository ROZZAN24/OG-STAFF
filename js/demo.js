/**
 * OG STAFF — Interactive Security Lab Demo Module
 * Provides live, verifiable demonstrations of:
 * 1. Authentic RSA Digital Signing
 * 2. Tamper Detection & Avalanche Effect
 * 3. Attacker Key Forgery Failure & Trust Distribution
 */

import {
  generateKeyPair,
  exportPublicKey,
  fingerprint,
  canonicalize,
  signStaff,
  verifyStaff,
  calculateSha256Hex
} from './crypto.js';

import {
  showToast,
  loadKeysFromStorage,
  saveKeysToStorage,
  escapeHtml
} from './common.js';

// State for Demo
let issuerKeyPair = {
  publicKey: null,
  privateKey: null,
  fingerprint: ''
};

let attackerKeyPair = {
  publicKey: null,
  privateKey: null,
  fingerprint: ''
};

let originalStaff = {
  staffId: 'STF-1001',
  staffName: 'Arun Kumar',
  department: 'Computer Science',
  designation: 'Assistant Professor',
  institution: 'Sample Engineering College',
  joiningDate: '2025-06-01',
  validUntil: '2027-06-01'
};

let originalCanonical = '';
let originalSignatureB64 = '';
let originalSha256 = '';

document.addEventListener('DOMContentLoaded', async () => {
  initEventListeners();
  await initIssuerKeys();
});

/**
 * Initialize Issuer Key pair
 */
async function initIssuerKeys() {
  const stored = loadKeysFromStorage();
  if (stored && stored.publicJwk && stored.privateJwk) {
    try {
      const { importPublicKey, importPrivateKey } = await import('./crypto.js');
      const pub = await importPublicKey(stored.publicJwk);
      const priv = await importPrivateKey(stored.privateJwk);
      const fp = await fingerprint(pub);
      issuerKeyPair = { publicKey: pub, privateKey: priv, fingerprint: fp.short };
    } catch {}
  }

  if (!issuerKeyPair.privateKey) {
    // Generate fresh demo key pair
    const kp = await generateKeyPair();
    const fp = await fingerprint(kp.publicKey);
    issuerKeyPair = { publicKey: kp.publicKey, privateKey: kp.privateKey, fingerprint: fp.short };
  }

  document.getElementById('demo-issuer-fp').textContent = issuerKeyPair.fingerprint;
}

function initEventListeners() {
  // Step 1
  document.getElementById('btn-demo-step1-generate')?.addEventListener('click', handleStep1Generate);

  // Step 2
  document.getElementById('btn-demo-quick-tamper')?.addEventListener('click', handleQuickTamper);
  document.getElementById('btn-demo-verify-tampered')?.addEventListener('click', handleVerifyTampered);
  document.getElementById('btn-demo-reset-tamper')?.addEventListener('click', handleResetTamper);

  // Input listeners on tamper fields to update live preview
  const tamperInputs = document.querySelectorAll('.tamper-field');
  tamperInputs.forEach(input => {
    input.addEventListener('input', updateTamperedPreview);
  });

  // Step 3
  document.getElementById('btn-demo-generate-attacker')?.addEventListener('click', handleStep3AttackerDemo);
}

/**
 * Step 1: Generate Authentic Signed ID
 */
async function handleStep1Generate() {
  const btn = document.getElementById('btn-demo-step1-generate');
  if (btn) btn.disabled = true;

  try {
    if (!issuerKeyPair.privateKey) {
      await initIssuerKeys();
    }

    originalCanonical = canonicalize(originalStaff);
    originalSignatureB64 = await signStaff(issuerKeyPair.privateKey, originalStaff);
    originalSha256 = await calculateSha256Hex(originalCanonical);

    // Verify right away to confirm valid baseline
    const baselineValid = await verifyStaff(issuerKeyPair.publicKey, originalStaff, originalSignatureB64);

    document.getElementById('step1-canonical-box').textContent = originalCanonical;
    document.getElementById('step1-sig-box').textContent = originalSignatureB64;
    document.getElementById('step1-hash-box').textContent = originalSha256.toUpperCase();
    document.getElementById('step1-result-badge').innerHTML = baselineValid 
      ? '<span class="badge badge-success">✔ SIGNATURE VALID (AUTHENTIC)</span>' 
      : '<span class="badge badge-error">✖ BASELINE ERROR</span>';

    // Populate Step 2 inputs
    populateTamperForm(originalStaff);
    updateTamperedPreview();

    // Enable Step 2 & 3 sections
    document.getElementById('demo-step2-card').style.opacity = '1';
    document.getElementById('demo-step2-card').style.pointerEvents = 'auto';
    document.getElementById('demo-step3-card').style.opacity = '1';
    document.getElementById('demo-step3-card').style.pointerEvents = 'auto';

    showToast('Step 1 complete: Authentic RSA signature generated and verified!', 'success');
  } catch (err) {
    showToast(`Step 1 error: ${err.message}`, 'error');
  } finally {
    if (btn) btn.disabled = false;
  }
}

/**
 * Populate Step 2 inputs
 */
function populateTamperForm(staff) {
  document.getElementById('tamper-id').value = staff.staffId;
  document.getElementById('tamper-name').value = staff.staffName;
  document.getElementById('tamper-dept').value = staff.department;
  document.getElementById('tamper-desig').value = staff.designation;
  document.getElementById('tamper-inst').value = staff.institution;
  document.getElementById('tamper-joining').value = staff.joiningDate;
  document.getElementById('tamper-valid').value = staff.validUntil;
}

/**
 * Quick 1-click tamper button
 */
function handleQuickTamper() {
  const desigInput = document.getElementById('tamper-desig');
  if (desigInput) {
    desigInput.value = 'Professor';
    desigInput.style.borderColor = 'var(--color-error)';
    desigInput.style.boxShadow = '0 0 10px rgba(255, 82, 82, 0.4)';
    updateTamperedPreview();
    showToast('Changed Designation: "Assistant Professor" → "Professor"', 'warning');
  }
}

/**
 * Reset tampered inputs to original
 */
function handleResetTamper() {
  populateTamperForm(originalStaff);
  document.querySelectorAll('.tamper-field').forEach(f => {
    f.style.borderColor = '';
    f.style.boxShadow = '';
  });
  updateTamperedPreview();
  document.getElementById('tamper-result-box').style.display = 'none';
  showToast('Tamper inputs reset to original authentic record.', 'info');
}

/**
 * Update side-by-side JSON & Hash preview
 */
async function updateTamperedPreview() {
  const tamperedStaff = getTamperedStaffValues();
  let tamperedCanonical = '';
  try {
    tamperedCanonical = canonicalize(tamperedStaff);
  } catch {
    tamperedCanonical = 'Error canonicalizing input';
  }

  document.getElementById('tamper-orig-json').textContent = originalCanonical;
  document.getElementById('tamper-curr-json').textContent = tamperedCanonical;

  // SHA-256 Hashes
  const tamperedSha256 = await calculateSha256Hex(tamperedCanonical);
  document.getElementById('tamper-orig-hash').textContent = originalSha256.toUpperCase();
  document.getElementById('tamper-curr-hash').textContent = tamperedSha256.toUpperCase();

  const isIdentical = originalCanonical === tamperedCanonical;
  const hashMatchBadge = document.getElementById('tamper-hash-match-badge');
  if (hashMatchBadge) {
    if (isIdentical) {
      hashMatchBadge.className = 'badge badge-success';
      hashMatchBadge.textContent = 'HASHES MATCH';
    } else {
      hashMatchBadge.className = 'badge badge-error';
      hashMatchBadge.textContent = 'AVALANCHE EFFECT: HASH CHANGED!';
    }
  }
}

function getTamperedStaffValues() {
  return {
    staffId: document.getElementById('tamper-id')?.value.trim() || '',
    staffName: document.getElementById('tamper-name')?.value.trim() || '',
    department: document.getElementById('tamper-dept')?.value.trim() || '',
    designation: document.getElementById('tamper-desig')?.value.trim() || '',
    institution: document.getElementById('tamper-inst')?.value.trim() || '',
    joiningDate: document.getElementById('tamper-joining')?.value || '',
    validUntil: document.getElementById('tamper-valid')?.value || ''
  };
}

/**
 * Step 2: Verify Tampered Record
 */
async function handleVerifyTampered() {
  if (!originalSignatureB64) {
    showToast('Please execute Step 1 first to create a baseline signature.', 'warning');
    return;
  }

  const tamperedStaff = getTamperedStaffValues();
  const resultBox = document.getElementById('tamper-result-box');
  const resultTitle = document.getElementById('tamper-result-title');
  const resultMsg = document.getElementById('tamper-result-msg');

  try {
    // Attempt verification with the ORIGINAL signature
    const isValid = await verifyStaff(issuerKeyPair.publicKey, tamperedStaff, originalSignatureB64);

    resultBox.style.display = 'block';
    if (!isValid) {
      resultBox.className = 'result-card state-invalid';
      resultTitle.textContent = 'TAMPERING DETECTED: INVALID SIGNATURE';
      resultMsg.innerHTML = `
        <strong>Result: crypto.subtle.verify() returned FALSE</strong><br>
        Because even a single character was changed, the SHA-256 digest of the tampered data no longer matches the digest encrypted into the RSA signature by the issuer's private key. The signature is mathematically invalid.
      `;
      showToast('Tampering detected! Digital signature verification failed.', 'error');
    } else {
      resultBox.className = 'result-card state-verified';
      resultTitle.textContent = 'SIGNATURE VALID: NO TAMPERING DETECTED';
      resultMsg.textContent = 'The data in the form matches the original signed record exactly.';
      showToast('Data matches original record.', 'success');
    }
  } catch (err) {
    showToast(`Verification error: ${err.message}`, 'error');
  }
}

/**
 * Step 3: Attacker Key Pair Simulation
 */
async function handleStep3AttackerDemo() {
  const btn = document.getElementById('btn-demo-generate-attacker');
  if (btn) btn.disabled = true;

  try {
    showToast('Generating distinct Attacker RSA-2048 key pair...', 'info');

    // 1. Generate an entirely separate attacker key pair
    attackerKeyPair = await generateKeyPair();
    const attackerFp = await fingerprint(attackerKeyPair.publicKey);
    attackerKeyPair.fingerprint = attackerFp.short;

    document.getElementById('demo-attacker-fp').textContent = attackerKeyPair.fingerprint;

    // 2. Attacker signs the staff record with their own private key
    const forgedSignature = await signStaff(attackerKeyPair.privateKey, originalStaff);
    document.getElementById('attacker-forged-sig').textContent = forgedSignature;

    // 3. Verifier checks forged signature using the LEGITIMATE ISSUER's public key
    const verifyWithIssuerKey = await verifyStaff(issuerKeyPair.publicKey, originalStaff, forgedSignature);

    // 4. Update UI
    const attackerResultBox = document.getElementById('attacker-result-box');
    attackerResultBox.style.display = 'block';

    if (!verifyWithIssuerKey) {
      attackerResultBox.className = 'result-card state-invalid';
      document.getElementById('attacker-result-title').textContent = 'FORGERY REJECTED: INVALID SIGNATURE';
      document.getElementById('attacker-result-msg').innerHTML = `
        <strong>Verification with Issuer Public Key: FAILED (false)</strong><br>
        The attacker successfully signed the data with their own private key, but the verifier validates against the 
        <strong>Issuer's trusted public key</strong> (FP: <code>${issuerKeyPair.fingerprint}</code>). 
        Since the attacker does not possess the issuer's private key, their signature is cryptographically rejected.
      `;
      showToast('Attacker signature successfully rejected by Issuer Public Key!', 'success');
    } else {
      // In theory should never occur under RSA-2048
      attackerResultBox.className = 'result-card state-verified';
      document.getElementById('attacker-result-title').textContent = 'UNEXPECTED: Key collision or identical key';
    }

  } catch (err) {
    showToast(`Attacker demo error: ${err.message}`, 'error');
  } finally {
    if (btn) btn.disabled = false;
  }
}
