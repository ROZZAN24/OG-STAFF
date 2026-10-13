/**
 * OG STAFF — Shared Utilities Module
 * Handles UI interactions, toasts, safe LocalStorage, tokens, date logic, and schema validation.
 */

export const STORAGE_KEYS = {
  KEYS: 'ogstaff_demo_keypair_v1',
  RECORDS: 'ogstaff_signed_records_v1',
  RECENT_IDS: 'ogstaff_recent_history_v1',
};

export const SECURITY_WARNING_TEXT = 
  "Educational demo only: this application stores the private key in your browser's LocalStorage. " +
  "Anyone with access to this browser profile or its storage may be able to extract it. " +
  "Production systems must protect signing keys using a secure server, an HSM, or an appropriate key-management service.";

/**
 * Escapes HTML characters to prevent XSS when inserting untrusted text
 * @param {string} str
 * @returns {string}
 */
export function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/**
 * Generates a clean, compact, Code 128-compatible record token
 * Format: OG-STF-<alphanumeric>
 * Code 128 handles this format cleanly with high print/scan reliability.
 * @param {string} staffId
 * @returns {string}
 */
export function generateRecordToken(staffId = '') {
  const cleanId = String(staffId).replace(/[^a-zA-Z0-9]/g, '').slice(0, 8) || 'ID';
  const randomPart = Math.random().toString(36).substring(2, 6).toUpperCase();
  const timePart = Date.now().toString(36).slice(-4).toUpperCase();
  return `OG-${cleanId}-${timePart}${randomPart}`;
}

/**
 * Validates date strings and checks expiration against current local calendar day.
 * Expiration policy: The ID remains valid through its stated validUntil (YYYY-MM-DD) date.
 * It becomes expired on the following calendar day.
 * @param {string} validUntilStr YYYY-MM-DD
 * @returns {{isValidDate: boolean, isExpired: boolean, daysRemaining: number}}
 */
export function checkExpiration(validUntilStr) {
  if (!validUntilStr || typeof validUntilStr !== 'string') {
    return { isValidDate: false, isExpired: true, daysRemaining: -999 };
  }

  // Parse YYYY-MM-DD
  const parts = validUntilStr.split('-');
  if (parts.length !== 3) {
    return { isValidDate: false, isExpired: true, daysRemaining: -999 };
  }

  const year = parseInt(parts[0], 10);
  const month = parseInt(parts[1], 10) - 1;
  const day = parseInt(parts[2], 10);

  const expiryDate = new Date(year, month, day, 23, 59, 59, 999);
  if (isNaN(expiryDate.getTime())) {
    return { isValidDate: false, isExpired: true, daysRemaining: -999 };
  }

  const now = new Date();
  const isExpired = now.getTime() > expiryDate.getTime();

  // Difference in whole days
  const diffMs = expiryDate.getTime() - now.getTime();
  const daysRemaining = Math.ceil(diffMs / (1000 * 60 * 60 * 24));

  return {
    isValidDate: true,
    isExpired,
    daysRemaining
  };
}

/**
 * Validates structure of a signed staff record payload
 * @param {object} payload
 * @returns {{isValid: boolean, error?: string}}
 */
export function validateSignedRecordSchema(payload) {
  if (!payload || typeof payload !== 'object') {
    return { isValid: false, error: 'Payload must be a valid JSON object.' };
  }

  if (payload.version !== 1) {
    return { isValid: false, error: 'Unsupported version. Expected version 1.' };
  }

  if (payload.algorithm !== 'RSASSA-PKCS1-v1_5' || payload.hash !== 'SHA-256') {
    return { isValid: false, error: 'Unsupported cryptographic algorithm or hash.' };
  }

  if (!payload.data || typeof payload.data !== 'object') {
    return { isValid: false, error: 'Missing or invalid staff "data" object.' };
  }

  const requiredFields = ['staffId', 'staffName', 'department', 'designation', 'institution', 'joiningDate', 'validUntil'];
  for (const field of requiredFields) {
    if (payload.data[field] === undefined || payload.data[field] === null || payload.data[field] === '') {
      return { isValid: false, error: `Missing required staff field: ${field}` };
    }
  }

  if (!payload.signature || typeof payload.signature !== 'string') {
    return { isValid: false, error: 'Missing or invalid digital signature string.' };
  }

  return { isValid: true };
}

/**
 * Toast notification dispatcher
 * @param {string} message
 * @param {'info'|'success'|'warning'|'error'} type
 * @param {number} durationMs
 */
export function showToast(message, type = 'info', durationMs = 4000) {
  let container = document.getElementById('toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    container.className = 'toast-container';
    document.body.appendChild(container);
  }

  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  
  const iconSpan = document.createElement('span');
  iconSpan.className = 'toast-icon';
  iconSpan.textContent = type === 'success' ? '✔' : type === 'error' ? '✖' : type === 'warning' ? '⚠' : 'ℹ';
  
  const msgSpan = document.createElement('span');
  msgSpan.className = 'toast-message';
  msgSpan.textContent = message;

  const closeBtn = document.createElement('button');
  closeBtn.className = 'toast-close';
  closeBtn.innerHTML = '&times;';
  closeBtn.onclick = () => toast.remove();

  toast.appendChild(iconSpan);
  toast.appendChild(msgSpan);
  toast.appendChild(closeBtn);
  container.appendChild(toast);

  setTimeout(() => {
    toast.classList.add('fade-out');
    setTimeout(() => toast.remove(), 400);
  }, durationMs);
}

/**
 * Safe LocalStorage helpers with try/catch
 */
export function getStorageItem(key, defaultValue = null) {
  try {
    const item = localStorage.getItem(key);
    return item ? JSON.parse(item) : defaultValue;
  } catch (err) {
    console.warn(`LocalStorage read error for ${key}:`, err);
    return defaultValue;
  }
}

export function setStorageItem(key, value) {
  try {
    localStorage.setItem(key, JSON.stringify(value));
    return true;
  } catch (err) {
    console.error(`LocalStorage write error for ${key}:`, err);
    showToast('Failed to save data to LocalStorage (quota exceeded or storage blocked).', 'error');
    return false;
  }
}

export function removeStorageItem(key) {
  try {
    localStorage.removeItem(key);
  } catch (err) {
    console.warn(`LocalStorage remove error for ${key}:`, err);
  }
}

/**
 * Key storage operations
 */
export function saveKeysToStorage(publicJwk, privateJwk, fingerprintStr = '') {
  const data = {
    publicJwk,
    privateJwk,
    algorithm: 'RSASSA-PKCS1-v1_5',
    hash: 'SHA-256',
    modulusLength: 2048,
    fingerprint: fingerprintStr,
    createdAt: new Date().toISOString()
  };
  return setStorageItem(STORAGE_KEYS.KEYS, data);
}

export function loadKeysFromStorage() {
  return getStorageItem(STORAGE_KEYS.KEYS, null);
}

export function clearKeysFromStorage() {
  removeStorageItem(STORAGE_KEYS.KEYS);
}

/**
 * Record storage operations (Token -> Full Signed Payload)
 */
export function saveSignedRecordToStorage(token, signedRecord) {
  const records = getStorageItem(STORAGE_KEYS.RECORDS, {});
  records[token] = {
    token,
    signedRecord,
    savedAt: new Date().toISOString()
  };
  return setStorageItem(STORAGE_KEYS.RECORDS, records);
}

export function getSignedRecordFromStorage(token) {
  const records = getStorageItem(STORAGE_KEYS.RECORDS, {});
  return records[token] ? records[token].signedRecord : null;
}

export function getAllStoredRecords() {
  return getStorageItem(STORAGE_KEYS.RECORDS, {});
}

/**
 * Recent IDs history operations
 */
export function saveRecentId(recordMetadata) {
  const history = getStorageItem(STORAGE_KEYS.RECENT_IDS, []);
  // Keep up to 20 recent items, prepend newest
  const filtered = history.filter(item => item.token !== recordMetadata.token);
  filtered.unshift({
    ...recordMetadata,
    createdAt: new Date().toISOString()
  });
  setStorageItem(STORAGE_KEYS.RECENT_IDS, filtered.slice(0, 20));
}

export function getRecentIds() {
  return getStorageItem(STORAGE_KEYS.RECENT_IDS, []);
}

export function deleteRecentId(token) {
  const history = getStorageItem(STORAGE_KEYS.RECENT_IDS, []);
  const updated = history.filter(item => item.token !== token);
  setStorageItem(STORAGE_KEYS.RECENT_IDS, updated);

  const records = getStorageItem(STORAGE_KEYS.RECORDS, {});
  if (records[token]) {
    delete records[token];
    setStorageItem(STORAGE_KEYS.RECORDS, records);
  }
}

export function clearRecentIds() {
  removeStorageItem(STORAGE_KEYS.RECENT_IDS);
  removeStorageItem(STORAGE_KEYS.RECORDS);
}

/**
 * Automatically highlights the active link in the navigation header
 */
export function initNavigation() {
  const currentPath = window.location.pathname.split('/').pop() || 'index.html';
  const navLinks = document.querySelectorAll('.nav-links a');
  navLinks.forEach(link => {
    const href = link.getAttribute('href');
    if (href === currentPath || (currentPath === '' && href === 'index.html')) {
      link.classList.add('active');
    } else {
      link.classList.remove('active');
    }
  });
}

// Automatically initialize navigation on DOMContentLoaded in browser environment
if (typeof document !== 'undefined') {
  document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
  });
}
