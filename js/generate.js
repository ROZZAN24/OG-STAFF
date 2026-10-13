/**
 * OG STAFF — Generate Page Logic
 * Handles key pair lifecycle, staff record validation, RSA signing,
 * Code 128 barcode generation, ID card rendering, PNG export, and printing.
 */

import {
  generateKeyPair,
  exportPublicKey,
  exportPrivateKey,
  importPublicKey,
  importPrivateKey,
  derivePublicKeyFromPrivateJwk,
  fingerprint,
  canonicalize,
  signStaff,
  verifyStaff,
  downloadJSON
} from './crypto.js';

import {
  showToast,
  generateRecordToken,
  saveKeysToStorage,
  loadKeysFromStorage,
  clearKeysFromStorage,
  saveSignedRecordToStorage,
  getSignedRecordFromStorage,
  saveRecentId,
  getRecentIds,
  deleteRecentId,
  clearRecentIds,
  escapeHtml,
  checkExpiration
} from './common.js';

// Active in-memory cryptographic keys
let activeKeyPair = {
  publicKey: null,
  privateKey: null,
  publicJwk: null,
  privateJwk: null,
  fingerprintStr: ''
};

let currentPhotoDataUrl = 'assets/placeholder-avatar.svg';
let currentSignedPayload = null;

document.addEventListener('DOMContentLoaded', async () => {
  initEventListeners();
  await tryRestoreKeys();
  renderRecentIdsTable();
});

/**
 * Attempt to restore keys from LocalStorage
 */
async function tryRestoreKeys() {
  const stored = loadKeysFromStorage();
  if (stored && stored.privateJwk && stored.publicJwk) {
    try {
      updateKeyStatusUI('loading', 'Restoring saved RSA key pair from LocalStorage...');
      const privateKey = await importPrivateKey(stored.privateJwk);
      const publicKey = await importPublicKey(stored.publicJwk);
      const fp = await fingerprint(publicKey);

      activeKeyPair = {
        publicKey,
        privateKey,
        publicJwk: stored.publicJwk,
        privateJwk: stored.privateJwk,
        fingerprintStr: fp.short
      };

      updateKeyStatusUI('ready', 'Active RSA-2048 key pair loaded from LocalStorage');
      updateKeyDetailsUI();
    } catch (err) {
      console.warn('Failed restoring stored keys:', err);
      updateKeyStatusUI('error', 'Stored keys could not be restored. Please generate a new key pair.');
    }
  } else {
    updateKeyStatusUI('none', 'No cryptographic keys found. Generate or import a key pair to begin.');
  }
}

/**
 * Initialize all button and form event listeners
 */
function initEventListeners() {
  // Key Operations
  document.getElementById('btn-generate-keys')?.addEventListener('click', handleGenerateKeys);
  document.getElementById('btn-export-pub')?.addEventListener('click', handleExportPublicKey);
  document.getElementById('btn-export-priv')?.addEventListener('click', handleExportPrivateKey);
  document.getElementById('btn-import-keys')?.addEventListener('click', () => {
    document.getElementById('import-file-input')?.click();
  });
  document.getElementById('import-file-input')?.addEventListener('change', handleImportKeyFile);
  document.getElementById('btn-clear-keys')?.addEventListener('click', handleClearKeys);

  // Photo Upload
  const photoInput = document.getElementById('staff-photo-input');
  photoInput?.addEventListener('change', handlePhotoUpload);
  document.getElementById('btn-remove-photo')?.addEventListener('click', () => {
    currentPhotoDataUrl = 'assets/placeholder-avatar.svg';
    const preview = document.getElementById('photo-preview-img');
    if (preview) preview.src = currentPhotoDataUrl;
    if (photoInput) photoInput.value = '';
    showToast('Photo reset to default placeholder avatar.', 'info');
  });

  // Form Submit
  const staffForm = document.getElementById('staff-form');
  staffForm?.addEventListener('submit', handleStaffFormSubmit);

  // Card Actions
  document.getElementById('btn-print-card')?.addEventListener('click', () => window.print());
  document.getElementById('btn-download-png')?.addEventListener('click', handleDownloadPng);
  document.getElementById('btn-download-json')?.addEventListener('click', handleDownloadJson);
  document.getElementById('btn-copy-sig')?.addEventListener('click', handleCopySignature);

  // History Actions
  document.getElementById('btn-clear-history')?.addEventListener('click', handleClearHistory);
}

/**
 * Generate a new RSA-2048 key pair
 */
async function handleGenerateKeys() {
  const btn = document.getElementById('btn-generate-keys');
  if (btn) btn.disabled = true;

  try {
    updateKeyStatusUI('loading', 'Generating 2048-bit RSA key pair via Web Crypto API...');
    const kp = await generateKeyPair();
    const pubJwk = await exportPublicKey(kp.publicKey, 'jwk');
    const privJwk = await exportPrivateKey(kp.privateKey);
    const fp = await fingerprint(kp.publicKey);

    activeKeyPair = {
      publicKey: kp.publicKey,
      privateKey: kp.privateKey,
      publicJwk: pubJwk,
      privateJwk: privJwk,
      fingerprintStr: fp.short
    };

    saveKeysToStorage(pubJwk, privJwk, fp.short);
    updateKeyStatusUI('ready', 'New RSA-2048 key pair generated and persisted to LocalStorage');
    updateKeyDetailsUI();
    showToast('RSA-2048 key pair successfully generated!', 'success');
  } catch (err) {
    updateKeyStatusUI('error', `Key generation failed: ${err.message}`);
    showToast(err.message, 'error');
  } finally {
    if (btn) btn.disabled = false;
  }
}

/**
 * Export Public Key as JWK
 */
function handleExportPublicKey() {
  if (!activeKeyPair.publicJwk) {
    showToast('No active public key available to export.', 'warning');
    return;
  }
  downloadJSON('og-staff-public-key.json', activeKeyPair.publicJwk);
  showToast('Public key downloaded (JWK format).', 'success');
}

/**
 * Export Private Key as JWK
 */
function handleExportPrivateKey() {
  if (!activeKeyPair.privateJwk) {
    showToast('No active private key available to export.', 'warning');
    return;
  }
  downloadJSON('og-staff-private-key.json', activeKeyPair.privateJwk);
  showToast('Private key downloaded (JWK format). Keep this secret!', 'warning');
}

/**
 * Import Key from selected file
 */
async function handleImportKeyFile(e) {
  const file = e.target.files?.[0];
  if (!file) return;

  try {
    const text = await file.text();
    let data;
    try {
      data = JSON.parse(text);
    } catch {
      throw new Error('Imported file is not valid JSON.');
    }

    if (data.d) {
      // Looks like a private JWK
      updateKeyStatusUI('loading', 'Importing private JWK and deriving public key...');
      const privateKey = await importPrivateKey(data);
      const publicKey = await derivePublicKeyFromPrivateJwk(data);
      const pubJwk = await exportPublicKey(publicKey, 'jwk');
      const fp = await fingerprint(publicKey);

      activeKeyPair = {
        publicKey,
        privateKey,
        publicJwk: pubJwk,
        privateJwk: data,
        fingerprintStr: fp.short
      };

      saveKeysToStorage(pubJwk, data, fp.short);
      updateKeyStatusUI('ready', 'Private key imported and public counterpart derived successfully');
      updateKeyDetailsUI();
      showToast('Private key imported successfully!', 'success');
    } else if (data.kty === 'RSA') {
      // Public JWK
      updateKeyStatusUI('loading', 'Importing public JWK...');
      const publicKey = await importPublicKey(data);
      const fp = await fingerprint(publicKey);

      activeKeyPair = {
        publicKey,
        privateKey: null,
        publicJwk: data,
        privateJwk: null,
        fingerprintStr: fp.short
      };

      updateKeyStatusUI('warning', 'Public key loaded. (Private key not present; cannot sign new records)');
      updateKeyDetailsUI();
      showToast('Public key imported (verification only).', 'info');
    } else {
      throw new Error('Unrecognized key structure in JSON file.');
    }
  } catch (err) {
    showToast(`Key import failed: ${err.message}`, 'error');
  } finally {
    e.target.value = '';
  }
}

/**
 * Clear stored keys
 */
function handleClearKeys() {
  if (!confirm('Are you sure you want to clear stored cryptographic keys from LocalStorage? You will need to generate or import new keys.')) {
    return;
  }

  clearKeysFromStorage();
  activeKeyPair = {
    publicKey: null,
    privateKey: null,
    publicJwk: null,
    privateJwk: null,
    fingerprintStr: ''
  };

  updateKeyStatusUI('none', 'No cryptographic keys active. Generate or import a key pair.');
  updateKeyDetailsUI();
  showToast('Stored keys cleared.', 'info');
}

/**
 * Updates Key status UI badge and message
 */
function updateKeyStatusUI(state, message) {
  const badge = document.getElementById('key-status-badge');
  const msgEl = document.getElementById('key-status-message');

  if (badge) {
    badge.className = 'badge';
    if (state === 'ready') {
      badge.classList.add('badge-success');
      badge.textContent = 'KEYS READY';
    } else if (state === 'loading') {
      badge.classList.add('badge-cyan');
      badge.textContent = 'PROCESSING...';
    } else if (state === 'warning') {
      badge.classList.add('badge-warning');
      badge.textContent = 'PUBLIC ONLY';
    } else if (state === 'error') {
      badge.classList.add('badge-error');
      badge.textContent = 'IMPORT ERROR';
    } else {
      badge.classList.add('badge-warning');
      badge.textContent = 'NO KEYS';
    }
  }

  if (msgEl) {
    msgEl.textContent = message;
  }
}

/**
 * Updates Key Details UI (Fingerprint, algorithm, buttons)
 */
function updateKeyDetailsUI() {
  const fpEl = document.getElementById('key-fingerprint-display');
  const exportPubBtn = document.getElementById('btn-export-pub');
  const exportPrivBtn = document.getElementById('btn-export-priv');

  if (fpEl) {
    fpEl.textContent = activeKeyPair.fingerprintStr || '—';
  }

  if (exportPubBtn) exportPubBtn.disabled = !activeKeyPair.publicKey;
  if (exportPrivBtn) exportPrivBtn.disabled = !activeKeyPair.privateKey;
}

/**
 * Photo upload handler
 */
function handlePhotoUpload(e) {
  const file = e.target.files?.[0];
  if (!file) return;

  if (!file.type.startsWith('image/')) {
    showToast('Please select a valid image file (PNG, JPEG, WebP).', 'error');
    return;
  }

  if (file.size > 2 * 1024 * 1024) {
    showToast('Image file size must be under 2MB.', 'error');
    return;
  }

  const reader = new FileReader();
  reader.onload = (evt) => {
    currentPhotoDataUrl = evt.target.result;
    const preview = document.getElementById('photo-preview-img');
    if (preview) preview.src = currentPhotoDataUrl;
    showToast('Photo uploaded for visual card display. Note: photo is NOT signed.', 'info');
  };
  reader.readAsDataURL(file);
}

/**
 * Form Submit & RSA Signing Handler
 */
async function handleStaffFormSubmit(e) {
  e.preventDefault();

  if (!activeKeyPair.privateKey) {
    showToast('Cannot sign: No active RSA private key available. Please generate or import keys first.', 'error');
    return;
  }

  const staff = {
    staffId: document.getElementById('staff-id').value.trim(),
    staffName: document.getElementById('staff-name').value.trim(),
    department: document.getElementById('staff-dept').value.trim(),
    designation: document.getElementById('staff-designation').value.trim(),
    institution: document.getElementById('staff-institution').value.trim(),
    joiningDate: document.getElementById('staff-joining').value,
    validUntil: document.getElementById('staff-valid').value
  };

  // Validation
  for (const [key, val] of Object.entries(staff)) {
    if (!val) {
      showToast(`Please fill in all required fields. Missing: ${key}`, 'error');
      return;
    }
  }

  if (staff.joiningDate > staff.validUntil) {
    showToast('Joining date cannot be after the validity expiration date.', 'error');
    return;
  }

  const generateBtn = document.getElementById('btn-submit-generate');
  if (generateBtn) generateBtn.disabled = true;

  try {
    // 1. Digital signature generation
    const signatureB64 = await signStaff(activeKeyPair.privateKey, staff);
    const token = generateRecordToken(staff.staffId);
    const canonicalJson = canonicalize(staff);

    // 2. Structured signed payload
    currentSignedPayload = {
      version: 1,
      algorithm: 'RSASSA-PKCS1-v1_5',
      hash: 'SHA-256',
      token,
      data: staff,
      signature: signatureB64,
      photo: currentPhotoDataUrl,
      issuerFingerprint: activeKeyPair.fingerprintStr,
      generatedAt: new Date().toISOString()
    };

    // 3. Persist record locally
    saveSignedRecordToStorage(token, currentSignedPayload);

    // 4. Render printable card & barcode
    renderIdCard(currentSignedPayload);

    // 5. Render Cryptography Info panel
    renderCryptoInfoPanel(canonicalJson, signatureB64);

    // 6. Save to history
    saveRecentId({
      token,
      staffId: staff.staffId,
      staffName: staff.staffName,
      department: staff.department,
      validUntil: staff.validUntil
    });
    renderRecentIdsTable();

    // Show card panel
    const cardContainer = document.getElementById('card-output-section');
    if (cardContainer) {
      cardContainer.style.display = 'block';
      cardContainer.scrollIntoView({ behavior: 'smooth' });
    }

    showToast(`Staff ID Card generated and signed with RSA-2048! Token: ${token}`, 'success');
  } catch (err) {
    console.error('Error during generation:', err);
    showToast(`Generation failed: ${err.message}`, 'error');
  } finally {
    if (generateBtn) generateBtn.disabled = false;
  }
}

/**
 * Renders the printable ID card DOM with Code 128 barcode
 */
function renderIdCard(payload) {
  const { data, token, photo, signature } = payload;

  document.getElementById('card-inst-display').textContent = data.institution;
  document.getElementById('card-photo-img').src = photo || 'assets/placeholder-avatar.svg';
  document.getElementById('card-name-display').textContent = data.staffName;
  document.getElementById('card-desig-display').textContent = data.designation;
  document.getElementById('card-id-display').textContent = data.staffId;
  document.getElementById('card-dept-display').textContent = data.department;
  document.getElementById('card-joining-display').textContent = data.joiningDate;
  document.getElementById('card-valid-display').textContent = data.validUntil;
  document.getElementById('card-token-display').textContent = `TOKEN: ${token}`;

  // Signature preview (first 10 and last 10 characters)
  const sigPreview = `${signature.substring(0, 10)}...${signature.substring(signature.length - 10)}`;
  document.getElementById('card-sig-preview').textContent = sigPreview;

  // Render Code 128 barcode using JsBarcode
  try {
    if (window.JsBarcode) {
      window.JsBarcode('#barcode-svg', token, {
        format: 'CODE128',
        width: 1.6,
        height: 48,
        displayValue: false,
        lineColor: '#000000',
        background: '#ffffff',
        margin: 2
      });
    } else {
      console.warn('JsBarcode library is not loaded on window.');
    }
  } catch (bErr) {
    console.error('Barcode rendering error:', bErr);
  }
}

/**
 * Updates Cryptography Info panel
 */
function renderCryptoInfoPanel(canonicalJson, signatureB64) {
  const canonEl = document.getElementById('crypto-canonical-json');
  const sigEl = document.getElementById('crypto-signature-b64');
  const fpEl = document.getElementById('crypto-fp-display');
  const sigLenEl = document.getElementById('crypto-sig-length');

  if (canonEl) canonEl.textContent = canonicalJson;
  if (sigEl) sigEl.textContent = signatureB64;
  if (fpEl) fpEl.textContent = activeKeyPair.fingerprintStr || '—';
  if (sigLenEl) sigLenEl.textContent = `${signatureB64.length} characters (256 raw bytes)`;
}

/**
 * High-resolution canvas PNG export
 */
async function handleDownloadPng() {
  if (!currentSignedPayload) {
    showToast('No generated card to download.', 'warning');
    return;
  }

  const { data, token, photo, signature } = currentSignedPayload;
  showToast('Rendering high-resolution ID card PNG...', 'info');

  try {
    const canvas = document.createElement('canvas');
    const width = 760;
    const height = 1080;
    canvas.width = width;
    canvas.height = height;
    const ctx = canvas.getContext('2d');

    // Background gradient
    const bgGrad = ctx.createLinearGradient(0, 0, width, height);
    bgGrad.addColorStop(0, '#102447');
    bgGrad.addColorStop(1, '#0b1b3a');
    ctx.fillStyle = bgGrad;
    ctx.fillRect(0, 0, width, height);

    // Border
    ctx.strokeStyle = '#00d4ff';
    ctx.lineWidth = 8;
    ctx.strokeRect(4, 4, width - 8, height - 8);

    // Header top accent line
    const accentGrad = ctx.createLinearGradient(0, 0, width, 0);
    accentGrad.addColorStop(0, '#00d4ff');
    accentGrad.addColorStop(0.5, '#0077b6');
    accentGrad.addColorStop(1, '#00e676');
    ctx.fillStyle = accentGrad;
    ctx.fillRect(4, 4, width - 8, 14);

    // Institution Header
    ctx.fillStyle = '#00d4ff';
    ctx.font = 'bold 30px Inter, sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText(data.institution.toUpperCase(), width / 2, 75);

    ctx.fillStyle = '#a8bad3';
    ctx.font = '600 16px Inter, sans-serif';
    ctx.fillText('OG STAFF DIGITAL IDENTITY CARD', width / 2, 105);

    ctx.strokeStyle = 'rgba(0, 212, 255, 0.3)';
    ctx.lineWidth = 2;
    ctx.beginPath();
    ctx.moveTo(30, 125);
    ctx.lineTo(width - 30, 125);
    ctx.stroke();

    // Staff Photo
    const photoImg = new Image();
    photoImg.crossOrigin = 'anonymous';
    photoImg.src = photo || 'assets/placeholder-avatar.svg';

    await new Promise((resolve) => {
      photoImg.onload = resolve;
      photoImg.onerror = resolve; // Continue even if photo load has issue
    });

    const photoX = (width - 220) / 2;
    const photoY = 150;
    const photoW = 220;
    const photoH = 220;

    ctx.save();
    ctx.strokeStyle = '#00d4ff';
    ctx.lineWidth = 4;
    ctx.strokeRect(photoX, photoY, photoW, photoH);
    ctx.drawImage(photoImg, photoX, photoY, photoW, photoH);
    ctx.restore();

    // Name & Designation
    ctx.fillStyle = '#ffffff';
    ctx.font = 'bold 36px Inter, sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText(data.staffName, width / 2, 420);

    ctx.fillStyle = '#00d4ff';
    ctx.font = '600 24px Inter, sans-serif';
    ctx.fillText(data.designation, width / 2, 458);

    // Details Table Box
    const tableY = 490;
    const rowH = 42;
    const rows = [
      ['Staff ID', data.staffId],
      ['Department', data.department],
      ['Date of Joining', data.joiningDate],
      ['Valid Until', data.validUntil],
    ];

    rows.forEach((row, i) => {
      const curY = tableY + i * rowH;
      // Border line
      ctx.strokeStyle = 'rgba(255, 255, 255, 0.1)';
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(60, curY + 10);
      ctx.lineTo(width - 60, curY + 10);
      ctx.stroke();

      ctx.fillStyle = '#a8bad3';
      ctx.font = '500 20px Inter, sans-serif';
      ctx.textAlign = 'left';
      ctx.fillText(row[0], 70, curY);

      ctx.fillStyle = '#ffffff';
      ctx.font = 'bold 20px Inter, sans-serif';
      ctx.textAlign = 'right';
      ctx.fillText(row[1], width - 70, curY);
    });

    // Barcode rendering onto canvas
    const barcodeBoxY = 690;
    const barcodeBoxH = 190;
    ctx.fillStyle = '#ffffff';
    ctx.fillRect(60, barcodeBoxY, width - 120, barcodeBoxH);
    ctx.strokeStyle = '#00d4ff';
    ctx.lineWidth = 2;
    ctx.strokeRect(60, barcodeBoxY, width - 120, barcodeBoxH);

    // Convert SVG barcode to image
    const barcodeSvg = document.getElementById('barcode-svg');
    if (barcodeSvg) {
      const svgString = new XMLSerializer().serializeToString(barcodeSvg);
      const svgBlob = new Blob([svgString], { type: 'image/svg+xml;charset=utf-8' });
      const svgUrl = URL.createObjectURL(svgBlob);
      const barcodeImg = new Image();
      await new Promise((resolve) => {
        barcodeImg.onload = resolve;
        barcodeImg.onerror = resolve;
        barcodeImg.src = svgUrl;
      });
      ctx.drawImage(barcodeImg, 80, barcodeBoxY + 15, width - 160, 110);
      URL.revokeObjectURL(svgUrl);
    }

    ctx.fillStyle = '#333333';
    ctx.font = 'bold 18px monospace';
    ctx.textAlign = 'center';
    ctx.fillText(`TOKEN: ${token}`, width / 2, barcodeBoxY + 160);

    // Footer info
    ctx.fillStyle = 'rgba(16, 36, 71, 0.95)';
    ctx.fillRect(4, height - 90, width - 8, 82);

    ctx.fillStyle = '#a8bad3';
    ctx.font = '16px Inter, sans-serif';
    ctx.textAlign = 'left';
    ctx.fillText('Digital Sig (RSA-2048 / SHA-256):', 30, height - 52);

    ctx.fillStyle = '#00d4ff';
    ctx.font = '16px monospace';
    const shortSig = `${signature.substring(0, 14)}...${signature.substring(signature.length - 14)}`;
    ctx.fillText(shortSig, 30, height - 25);

    ctx.fillStyle = '#a8bad3';
    ctx.textAlign = 'right';
    ctx.fillText(`Issuer FP: ${activeKeyPair.fingerprintStr || 'N/A'}`, width - 30, height - 38);

    // Convert to downloadable file
    canvas.toBlob((blob) => {
      if (!blob) {
        showToast('PNG generation failed.', 'error');
        return;
      }
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `staff-id-${data.staffId}.png`;
      a.click();
      URL.revokeObjectURL(url);
      showToast('ID card PNG downloaded successfully!', 'success');
    }, 'image/png');
  } catch (err) {
    console.error('PNG export error:', err);
    showToast(`Failed to export PNG: ${err.message}`, 'error');
  }
}

/**
 * Download signed record JSON
 */
function handleDownloadJson() {
  if (!currentSignedPayload) {
    showToast('No record available to download.', 'warning');
    return;
  }
  const filename = `staff-${currentSignedPayload.data.staffId}-signed.json`;
  downloadJSON(filename, currentSignedPayload);
  showToast('Signed record JSON downloaded.', 'success');
}

/**
 * Copy Base64 signature
 */
function handleCopySignature() {
  if (!currentSignedPayload) return;
  navigator.clipboard.writeText(currentSignedPayload.signature)
    .then(() => showToast('Base64 signature copied to clipboard!', 'success'))
    .catch(() => showToast('Failed to copy to clipboard.', 'error'));
}

/**
 * Render Recent IDs Table
 */
function renderRecentIdsTable() {
  const container = document.getElementById('recent-ids-tbody');
  if (!container) return;

  const history = getRecentIds();
  container.innerHTML = '';

  if (history.length === 0) {
    container.innerHTML = `
      <tr>
        <td colspan="6" style="text-align: center; color: var(--text-dim); padding: 1.5rem;">
          No staff ID cards generated yet.
        </td>
      </tr>
    `;
    return;
  }

  history.forEach(item => {
    const tr = document.createElement('tbody tr');
    const trEl = document.createElement('tr');

    const expCheck = checkExpiration(item.validUntil);
    const expBadge = expCheck.isExpired 
      ? '<span class="badge badge-warning">EXPIRED</span>' 
      : '<span class="badge badge-success">ACTIVE</span>';

    trEl.innerHTML = `
      <td><strong>${escapeHtml(item.staffId)}</strong></td>
      <td>${escapeHtml(item.staffName)}</td>
      <td>${escapeHtml(item.department)}</td>
      <td>${escapeHtml(item.validUntil)} ${expBadge}</td>
      <td><span style="font-family: monospace; font-size: 0.8rem; color: var(--cyan-accent);">${escapeHtml(item.token)}</span></td>
      <td>
        <div class="btn-group" style="gap: 0.4rem;">
          <button class="btn btn-secondary btn-sm btn-view-recent" data-token="${escapeHtml(item.token)}">View</button>
          <button class="btn btn-danger btn-sm btn-del-recent" data-token="${escapeHtml(item.token)}">Delete</button>
        </div>
      </td>
    `;

    // View button
    trEl.querySelector('.btn-view-recent')?.addEventListener('click', () => {
      const fullRecord = getSignedRecordFromStorage(item.token);
      if (fullRecord) {
        currentSignedPayload = fullRecord;
        renderIdCard(fullRecord);
        renderCryptoInfoPanel(canonicalize(fullRecord.data), fullRecord.signature);
        const cardSection = document.getElementById('card-output-section');
        if (cardSection) {
          cardSection.style.display = 'block';
          cardSection.scrollIntoView({ behavior: 'smooth' });
        }
        showToast(`Loaded ID card for ${fullRecord.data.staffName}`, 'info');
      } else {
        showToast('Record payload not found in LocalStorage.', 'error');
      }
    });

    // Delete button
    trEl.querySelector('.btn-del-recent')?.addEventListener('click', () => {
      deleteRecentId(item.token);
      renderRecentIdsTable();
      showToast('Record removed from history.', 'info');
    });

    container.appendChild(trEl);
  });
}

/**
 * Clear history handler
 */
function handleClearHistory() {
  if (!confirm('Are you sure you want to clear all recent generated ID records?')) return;
  clearRecentIds();
  renderRecentIdsTable();
  showToast('Generation history cleared.', 'info');
}
