/**
 * OG STAFF — Verification Logic Module
 * Implements trusted public key management, live camera Code 128 scanning,
 * barcode image upload decoding, manual JSON verification, and educational step logging.
 */

import {
  importPublicKey,
  fingerprint,
  canonicalize,
  verifyStaff,
  calculateSha256Hex
} from './crypto.js';

import {
  showToast,
  loadKeysFromStorage,
  getSignedRecordFromStorage,
  validateSignedRecordSchema,
  checkExpiration,
  escapeHtml
} from './common.js';

// Active Trusted Verification Key
let trustedPublicKey = null;
let trustedKeyFingerprint = '';

// ZXing Scanner Instance for Code 128
let codeReader = null;
let isScanning = false;

document.addEventListener('DOMContentLoaded', async () => {
  initTabs();
  initTrustedKeyPanel();
  initManualVerification();
  initCameraScanner();
  initImageUploadScanner();
  await tryLoadDefaultTrustedKey();
});

/**
 * Tab switcher
 */
function initTabs() {
  const tabBtns = document.querySelectorAll('.tab-btn');
  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const targetTab = btn.getAttribute('data-tab');
      tabBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');

      document.querySelectorAll('.tab-pane').forEach(pane => {
        pane.classList.remove('active');
      });
      document.getElementById(targetTab)?.classList.add('active');

      // Stop camera if moving away from camera tab
      if (targetTab !== 'tab-camera' && isScanning) {
        stopCameraScanning();
      }
    });
  });
}

/**
 * Load default public key from LocalStorage if available
 */
async function tryLoadDefaultTrustedKey() {
  const stored = loadKeysFromStorage();
  if (stored && stored.publicJwk) {
    try {
      trustedPublicKey = await importPublicKey(stored.publicJwk);
      const fp = await fingerprint(trustedPublicKey);
      trustedKeyFingerprint = fp.short;
      updateTrustedKeyUI();
    } catch (err) {
      console.warn('Failed loading stored public key:', err);
    }
  } else {
    updateTrustedKeyUI();
  }
}

/**
 * Trusted Public Key Panel Listeners
 */
function initTrustedKeyPanel() {
  document.getElementById('btn-use-stored-key')?.addEventListener('click', async () => {
    await tryLoadDefaultTrustedKey();
    if (trustedPublicKey) {
      showToast('Loaded active issuer public key from LocalStorage.', 'success');
    } else {
      showToast('No public key found in LocalStorage. Please import a public key.', 'warning');
    }
  });

  document.getElementById('btn-import-pub-file')?.addEventListener('click', () => {
    document.getElementById('pub-key-file-input')?.click();
  });

  document.getElementById('pub-key-file-input')?.addEventListener('change', async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      const text = await file.text();
      trustedPublicKey = await importPublicKey(text);
      const fp = await fingerprint(trustedPublicKey);
      trustedKeyFingerprint = fp.short;
      updateTrustedKeyUI();
      showToast('Trusted public key imported from file successfully!', 'success');
    } catch (err) {
      showToast(`Key import failed: ${err.message}`, 'error');
    } finally {
      e.target.value = '';
    }
  });

  document.getElementById('btn-paste-key')?.addEventListener('click', async () => {
    const keyText = prompt('Paste Public Key JWK (JSON) or Base64 SPKI:');
    if (!keyText) return;
    try {
      trustedPublicKey = await importPublicKey(keyText.trim());
      const fp = await fingerprint(trustedPublicKey);
      trustedKeyFingerprint = fp.short;
      updateTrustedKeyUI();
      showToast('Public key imported successfully!', 'success');
    } catch (err) {
      showToast(`Key import failed: ${err.message}`, 'error');
    }
  });
}

/**
 * Updates Trusted Public Key UI
 */
function updateTrustedKeyUI() {
  const fpEl = document.getElementById('trusted-key-fingerprint');
  const statusEl = document.getElementById('trusted-key-status');
  const alertEl = document.getElementById('trusted-key-warning');

  if (trustedPublicKey) {
    if (fpEl) fpEl.textContent = trustedKeyFingerprint;
    if (statusEl) {
      statusEl.className = 'badge badge-success';
      statusEl.textContent = 'TRUSTED KEY ACTIVE';
    }
    if (alertEl) alertEl.style.display = 'none';
  } else {
    if (fpEl) fpEl.textContent = 'None';
    if (statusEl) {
      statusEl.className = 'badge badge-error';
      statusEl.textContent = 'NO KEY CONFIGURED';
    }
    if (alertEl) alertEl.style.display = 'flex';
  }
}

/**
 * Camera Scanner Tab (Using ZXing BrowserMultiFormatReader for Code 128)
 */
function initCameraScanner() {
  const startBtn = document.getElementById('btn-start-camera');
  const stopBtn = document.getElementById('btn-stop-camera');

  startBtn?.addEventListener('click', startCameraScanning);
  stopBtn?.addEventListener('click', stopCameraScanning);
}

async function startCameraScanning() {
  if (isScanning) return;

  const videoEl = document.getElementById('scanner-video');
  const placeholderEl = document.getElementById('scanner-placeholder');
  const laserEl = document.getElementById('scanner-laser');
  const statusEl = document.getElementById('scanner-status-text');

  if (!window.ZXing) {
    showToast('Barcode scanner library (ZXing) is not loaded. Check internet connection.', 'error');
    return;
  }

  try {
    if (!codeReader) {
      codeReader = new window.ZXing.BrowserMultiFormatReader();
    }

    if (statusEl) statusEl.textContent = 'Requesting camera permissions...';
    
    // Check available devices
    const videoInputDevices = await codeReader.listVideoInputDevices();
    if (!videoInputDevices || videoInputDevices.length === 0) {
      throw new Error('No camera devices found on this computer/device.');
    }

    // Prefer back-facing camera or first available
    const selectedDeviceId = videoInputDevices[videoInputDevices.length - 1].deviceId;

    if (videoEl) videoEl.style.display = 'block';
    if (placeholderEl) placeholderEl.style.display = 'none';
    if (laserEl) laserEl.style.display = 'block';
    if (statusEl) statusEl.textContent = 'Scanning for Code 128 barcode... Hold steady';

    isScanning = true;
    document.getElementById('btn-start-camera').disabled = true;
    document.getElementById('btn-stop-camera').disabled = false;

    codeReader.decodeFromVideoDevice(selectedDeviceId, videoEl, (result, err) => {
      if (result) {
        const decodedText = result.getText();
        console.log('Barcode Decoded successfully:', decodedText);
        stopCameraScanning();
        handleScannedBarcodeToken(decodedText);
      }
    });

  } catch (err) {
    console.error('Camera error:', err);
    if (statusEl) statusEl.textContent = `Camera error: ${err.message}`;
    showToast(`Camera access failed: ${err.message}`, 'error');
    stopCameraScanning();
  }
}

function stopCameraScanning() {
  if (codeReader && isScanning) {
    codeReader.reset();
  }
  isScanning = false;

  const videoEl = document.getElementById('scanner-video');
  const placeholderEl = document.getElementById('scanner-placeholder');
  const laserEl = document.getElementById('scanner-laser');
  const statusEl = document.getElementById('scanner-status-text');
  const startBtn = document.getElementById('btn-start-camera');
  const stopBtn = document.getElementById('btn-stop-camera');

  if (videoEl) videoEl.style.display = 'none';
  if (placeholderEl) placeholderEl.style.display = 'block';
  if (laserEl) laserEl.style.display = 'none';
  if (statusEl) statusEl.textContent = 'Camera is idle.';
  if (startBtn) startBtn.disabled = false;
  if (stopBtn) stopBtn.disabled = true;
}

/**
 * Handle Scanned Token from Camera or Image Upload
 */
async function handleScannedBarcodeToken(rawText) {
  const token = rawText.trim();
  document.getElementById('scanned-token-output').textContent = token;

  // 1. Try to find local signed record
  const localRecord = getSignedRecordFromStorage(token);

  if (!localRecord) {
    renderVerificationResult({
      status: 'ERROR',
      title: 'RECORD NOT FOUND ON THIS DEVICE',
      message: `Decoded barcode token "${token}", but no matching signed staff record exists in this browser's LocalStorage. For cross-device verification, please use the Manual Verification tab to paste/import the signed JSON record.`,
      untrustedStaff: { staffId: token, staffName: 'Unknown', department: 'Unknown' },
      logs: [
        { num: 1, text: `Successfully decoded Code 128 barcode token: ${token}`, pass: true },
        { num: 2, text: 'Querying LocalStorage for signed staff payload under token...', pass: false },
        { num: 3, text: 'Payload not found locally. Cryptographic verification cannot proceed without staff record and signature.', pass: false }
      ]
    });
    return;
  }

  // 2. Perform full cryptographic verification
  await executeVerificationProcess(localRecord);
}

/**
 * Barcode Image Upload Scanner Tab
 */
function initImageUploadScanner() {
  const uploadInput = document.getElementById('barcode-image-file');
  const previewImg = document.getElementById('upload-preview-img');

  uploadInput?.addEventListener('change', async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = async (evt) => {
      const dataUrl = evt.target.result;
      if (previewImg) {
        previewImg.src = dataUrl;
        previewImg.style.display = 'block';
      }

      if (!window.ZXing) {
        showToast('ZXing library not loaded.', 'error');
        return;
      }

      try {
        const imgReader = new window.ZXing.BrowserMultiFormatReader();
        const imgEl = new Image();
        imgEl.src = dataUrl;
        await new Promise(res => { imgEl.onload = res; });

        const result = await imgReader.decodeFromImageElement(imgEl);
        if (result) {
          const decoded = result.getText();
          showToast(`Barcode decoded: ${decoded}`, 'success');
          handleScannedBarcodeToken(decoded);
        }
      } catch (decodeErr) {
        console.warn('Image decode error:', decodeErr);
        renderVerificationResult({
          status: 'ERROR',
          title: 'UNREADABLE BARCODE IMAGE',
          message: 'Could not detect or decode a valid Code 128 barcode in the uploaded image. Please ensure the barcode is clear, well-lit, and uncropped.',
          untrustedStaff: null,
          logs: [
            { num: 1, text: 'Loading image and parsing pixels...', pass: true },
            { num: 2, text: 'Searching for Code 128 patterns: No valid barcode pattern detected.', pass: false }
          ]
        });
      }
    };
    reader.readAsDataURL(file);
  });
}

/**
 * Manual Verification Tab
 */
function initManualVerification() {
  document.getElementById('btn-verify-manual')?.addEventListener('click', handleManualVerify);
  document.getElementById('btn-clear-manual')?.addEventListener('click', () => {
    document.getElementById('manual-json-input').value = '';
    document.getElementById('manual-sig-input').value = '';
    document.getElementById('verification-result-section').style.display = 'none';
  });

  document.getElementById('btn-load-example')?.addEventListener('click', handleLoadExample);
  document.getElementById('btn-import-signed-json')?.addEventListener('click', () => {
    document.getElementById('import-json-file-input')?.click();
  });

  document.getElementById('import-json-file-input')?.addEventListener('change', async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      const text = await file.text();
      const parsed = JSON.parse(text);
      await executeVerificationProcess(parsed);
    } catch (err) {
      showToast(`Failed to parse signed JSON file: ${err.message}`, 'error');
    } finally {
      e.target.value = '';
    }
  });
}

/**
 * Load a real example into the manual verification form
 */
function handleLoadExample() {
  const records = getSignedRecordFromStorage();
  const allStored = Object.values(window.localStorage)
    .map(val => { try { return JSON.parse(val); } catch { return null; } })
    .filter(Boolean);

  // Look for records in ogstaff_signed_records_v1
  let sample = null;
  try {
    const rawRecs = JSON.parse(localStorage.getItem('ogstaff_signed_records_v1') || '{}');
    const keys = Object.keys(rawRecs);
    if (keys.length > 0) {
      sample = rawRecs[keys[0]].signedRecord;
    }
  } catch {}

  if (sample) {
    document.getElementById('manual-json-input').value = JSON.stringify(sample.data, null, 2);
    document.getElementById('manual-sig-input').value = sample.signature;
    showToast('Loaded active generated record from LocalStorage.', 'info');
  } else {
    // Provide template
    const template = {
      staffId: 'STF-1001',
      staffName: 'Arun Kumar',
      department: 'Computer Science',
      designation: 'Assistant Professor',
      institution: 'Sample Engineering College',
      joiningDate: '2025-06-01',
      validUntil: '2027-06-01'
    };
    document.getElementById('manual-json-input').value = JSON.stringify(template, null, 2);
    document.getElementById('manual-sig-input').value = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA... (generate a card first for matching signature)';
    showToast('Loaded template. Generate a card on the Generate page for an active matching signature.', 'warning');
  }
}

/**
 * Manual form verification button click
 */
async function handleManualVerify() {
  const jsonText = document.getElementById('manual-json-input')?.value.trim();
  const sigText = document.getElementById('manual-sig-input')?.value.trim();

  if (!jsonText || !sigText) {
    showToast('Please provide both Staff JSON Data and the Base64 signature.', 'error');
    return;
  }

  let staffData;
  try {
    staffData = JSON.parse(jsonText);
  } catch (err) {
    showToast('Staff Data is not valid JSON.', 'error');
    return;
  }

  const payload = {
    version: 1,
    algorithm: 'RSASSA-PKCS1-v1_5',
    hash: 'SHA-256',
    data: staffData,
    signature: sigText
  };

  await executeVerificationProcess(payload);
}

/**
 * Master Verification Pipeline
 * Performs real cryptographic verification using the trusted public key
 * and independent expiration date analysis.
 */
async function executeVerificationProcess(payload) {
  const logs = [];

  // Step 1: Validate payload format
  logs.push({ num: 1, text: 'Step 1: Extract payload and signature.', pass: true });

  const schemaValidation = validateSignedRecordSchema(payload);
  if (!schemaValidation.isValid) {
    renderVerificationResult({
      status: 'ERROR',
      title: 'INVALID PAYLOAD SCHEMA',
      message: `Schema error: ${schemaValidation.error}`,
      untrustedStaff: payload.data || null,
      logs: [
        ...logs,
        { num: 2, text: `Schema validation failed: ${schemaValidation.error}`, pass: false }
      ]
    });
    return;
  }

  const staff = payload.data;
  const signatureB64 = payload.signature;
  logs.push({ num: 2, text: 'Step 2: Required canonical fields present and format validated.', pass: true });

  // Step 3: Check trusted public key
  if (!trustedPublicKey) {
    renderVerificationResult({
      status: 'ERROR',
      title: 'MISSING TRUSTED PUBLIC KEY',
      message: 'No trusted public key has been configured. The verifier cannot verify signatures without a trusted institutional public key.',
      untrustedStaff: staff,
      logs: [
        ...logs,
        { num: 3, text: 'Checking trusted public key: No public key loaded.', pass: false }
      ]
    });
    return;
  }

  // Step 4: Canonicalize JSON
  let canonicalJson = '';
  try {
    canonicalJson = canonicalize(staff);
    logs.push({ 
      num: 3, 
      text: 'Step 3: Rebuilt canonical JSON with strict field order.', 
      code: canonicalJson, 
      pass: true 
    });
  } catch (cErr) {
    renderVerificationResult({
      status: 'ERROR',
      title: 'CANONICALIZATION FAILED',
      message: cErr.message,
      untrustedStaff: staff,
      logs: [
        ...logs,
        { num: 3, text: `Canonicalization error: ${cErr.message}`, pass: false }
      ]
    });
    return;
  }

  // Step 5: Encode UTF-8
  logs.push({ num: 4, text: 'Step 4: Encoded canonical JSON string to UTF-8 bytes using TextEncoder.', pass: true });

  // Step 6: Educational SHA-256 Digest
  const sha256Hex = await calculateSha256Hex(canonicalJson);
  logs.push({ 
    num: 5, 
    text: 'Step 5: Calculated SHA-256 digest of canonical message (for verification logging):', 
    code: sha256Hex.toUpperCase(), 
    pass: true 
  });

  // Step 7: Cryptographic verification via Web Crypto API
  logs.push({ num: 6, text: `Step 6: Executing crypto.subtle.verify() using trusted public key (FP: ${trustedKeyFingerprint})...`, pass: true });
  
  let isSignatureValid = false;
  try {
    isSignatureValid = await verifyStaff(trustedPublicKey, staff, signatureB64);
  } catch (vErr) {
    isSignatureValid = false;
  }

  if (!isSignatureValid) {
    logs.push({ 
      num: 7, 
      text: 'Step 7: RSASSA-PKCS1-v1_5 signature check FAILED. The digital signature does NOT match the canonical data.', 
      pass: false 
    });

    renderVerificationResult({
      status: 'INVALID',
      title: 'INVALID — Signature Mismatch',
      message: 'The cryptographic signature is INVALID. The staff data has been altered, forged, or signed with an untrusted private key. All extracted data must be treated as untrusted.',
      untrustedStaff: staff,
      logs
    });
    return;
  }

  logs.push({ 
    num: 7, 
    text: 'Step 7: RSASSA-PKCS1-v1_5 signature check PASSED. Data authenticity & integrity verified!', 
    pass: true 
  });

  // Step 8: Independent Expiration Date Checking
  const expiration = checkExpiration(staff.validUntil);
  if (expiration.isExpired) {
    logs.push({ 
      num: 8, 
      text: `Step 8: Expiration check: ID expired on ${staff.validUntil}.`, 
      pass: false 
    });

    renderVerificationResult({
      status: 'EXPIRED',
      title: 'EXPIRED — Signature Valid, Validity Period Ended',
      message: `The digital signature is authentic and untampered, but this staff ID card expired on ${staff.validUntil}. It was authentic at issuance, but is no longer valid for active access.`,
      untrustedStaff: staff,
      isAuthentic: true,
      logs
    });
    return;
  }

  logs.push({ 
    num: 8, 
    text: `Step 8: Expiration check: Card is ACTIVE (valid until ${staff.validUntil}, ${expiration.daysRemaining} days remaining).`, 
    pass: true 
  });

  // Final Success State
  renderVerificationResult({
    status: 'VERIFIED',
    title: 'VERIFIED — Signature Valid & Identity Active',
    message: 'The RSA digital signature is mathematically valid, matching the trusted public key. The record is authentic and currently active.',
    untrustedStaff: staff,
    isAuthentic: true,
    logs
  });
}

/**
 * Renders the Verification Result Card & Log
 */
function renderVerificationResult({ status, title, message, untrustedStaff, isAuthentic = false, logs = [] }) {
  const section = document.getElementById('verification-result-section');
  if (!section) return;

  section.style.display = 'block';
  section.scrollIntoView({ behavior: 'smooth' });

  const card = document.getElementById('result-card');
  const titleEl = document.getElementById('result-title');
  const msgEl = document.getElementById('result-message');
  const iconEl = document.getElementById('result-icon');
  const extractedContainer = document.getElementById('extracted-staff-details');
  const logStepsContainer = document.getElementById('verification-log-steps');

  // Status Classes
  card.className = `result-card state-${status.toLowerCase()}`;
  titleEl.textContent = title;
  msgEl.textContent = message;

  if (status === 'VERIFIED') {
    iconEl.textContent = '✔';
  } else if (status === 'EXPIRED') {
    iconEl.textContent = '⏱';
  } else if (status === 'INVALID') {
    iconEl.textContent = '✖';
  } else {
    iconEl.textContent = '⚠';
  }

  // Extracted Details Display
  if (untrustedStaff && extractedContainer) {
    extractedContainer.innerHTML = `
      <div style="margin-top: 1.25rem; padding: 1rem; background-color: rgba(16, 36, 71, 0.7); border-radius: 8px; border: 1px solid rgba(0, 212, 255, 0.15);">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem;">
          <span style="font-weight: 700; font-size: 0.85rem; color: var(--text-muted); text-transform: uppercase;">
            ${isAuthentic ? 'Authentic Verified Staff Record' : 'Untrusted Extracted Data'}
          </span>
          <span class="badge ${isAuthentic ? 'badge-success' : 'badge-error'}">
            ${isAuthentic ? 'AUTHENTIC' : 'UNVERIFIED / UNTRUSTED'}
          </span>
        </div>
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem; font-size: 0.88rem;">
          <div><strong style="color: var(--text-muted);">Staff ID:</strong> ${escapeHtml(untrustedStaff.staffId)}</div>
          <div><strong style="color: var(--text-muted);">Name:</strong> ${escapeHtml(untrustedStaff.staffName)}</div>
          <div><strong style="color: var(--text-muted);">Department:</strong> ${escapeHtml(untrustedStaff.department)}</div>
          <div><strong style="color: var(--text-muted);">Designation:</strong> ${escapeHtml(untrustedStaff.designation)}</div>
          <div><strong style="color: var(--text-muted);">Institution:</strong> ${escapeHtml(untrustedStaff.institution)}</div>
          <div><strong style="color: var(--text-muted);">Valid Until:</strong> ${escapeHtml(untrustedStaff.validUntil)}</div>
        </div>
      </div>
    `;
  } else if (extractedContainer) {
    extractedContainer.innerHTML = '';
  }

  // Step-by-Step Verification Log Rendering
  if (logStepsContainer) {
    logStepsContainer.innerHTML = '';
    logs.forEach(step => {
      const li = document.createElement('li');
      li.className = `log-step ${step.pass ? 'pass' : 'fail'}`;

      let codeHtml = '';
      if (step.code) {
        codeHtml = `<code class="log-step-code">${escapeHtml(step.code)}</code>`;
      }

      li.innerHTML = `
        <div class="log-step-num">${step.num}</div>
        <div class="log-step-text">
          ${escapeHtml(step.text)}
          ${codeHtml}
        </div>
      `;
      logStepsContainer.appendChild(li);
    });
  }
}
