'use strict';

// Ensure self.window is defined for the JSEncrypt library to work within the web worker.
self.window = self;

// Import the JSEncrypt library via HTTPS
self.importScripts('https://cdnjs.cloudflare.com/ajax/libs/jsencrypt/2.3.1/jsencrypt.min.js');

let crypt = null;
let privateKey = null;

// Listen for messages from the UI thread
self.addEventListener('message', (event) => {
  const data = event.data;

  // Validate the incoming message format
  if (!Array.isArray(data) || data.length < 2) {
    postMessage(['error', 'Invalid message format']);
    return;
  }

  // Destructure parameters: messageType, messageId, and optionally text and key
  const [messageType, messageId, text, key] = data;
  let result;

  try {
    switch (messageType) {
      case 'generate-keys':
        result = generateKeypair();
        break;
      case 'encrypt':
        if (!text || !key) {
          throw new Error('Encryption requires both text and a public key.');
        }
        result = encrypt(text, key);
        break;
      case 'decrypt':
        if (!text) {
          throw new Error('Decryption requires text.');
        }
        result = decrypt(text);
        break;
      default:
        throw new Error(`Unknown message type: ${messageType}`);
    }
  } catch (error) {
    result = { error: error.message };
  }

  // Return the result with the original messageId so the UI thread can correlate responses
  postMessage([messageId, result]);
});

/**
 * Generate and store an RSA keypair.
 * Returns the public key (the private key is stored internally).
 *
 * @returns {string} The public key.
 */
function generateKeypair() {
  crypt = new JSEncrypt({ default_key_size: 2056 });
  privateKey = crypt.getPrivateKey();
  return crypt.getPublicKey();
}

/**
 * Encrypt the provided plaintext using the destination's public key.
 *
 * @param {string} content - The plaintext message to encrypt.
 * @param {string} publicKey - The public key to use for encryption.
 * @returns {string} The encrypted ciphertext.
 */
function encrypt(content, publicKey) {
  crypt.setKey(publicKey);
  const encrypted = crypt.encrypt(content);
  if (!encrypted) {
    throw new Error('Encryption failed.');
  }
  return encrypted;
}

/**
 * Decrypt the provided ciphertext using the stored private key.
 *
 * @param {string} content - The ciphertext to decrypt.
 * @returns {string} The decrypted plaintext.
 */
function decrypt(content) {
  if (!privateKey) {
    throw new Error('Private key not generated. Please generate keys first.');
  }
  crypt.setKey(privateKey);
  const decrypted = crypt.decrypt(content);
  if (!decrypted) {
    throw new Error('Decryption failed.');
  }
  return decrypted;
}
