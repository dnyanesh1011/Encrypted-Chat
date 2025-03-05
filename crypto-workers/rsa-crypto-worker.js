'use strict';

// Ensure self.window is defined for the JSEncrypt library to work within the web worker.
self.window = self;

// Import the JSEncrypt library via HTTPS
self.importScripts('https://cdnjs.cloudflare.com/ajax/libs/jsencrypt/2.3.1/jsencrypt.min.js');

let crypt = null;
let privateKey = null;

// Maximum allowed message length
const MAX_MESSAGE_LENGTH = 10000;

// Secure key storage (basic implementation)
function secureKeyStorage(key) {
  // In a real-world scenario, use more advanced key protection
  return key;
}

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
  // Increase key size for stronger encryption
  crypt = new JSEncrypt({ default_key_size: 4096 });
  
  // Validate key generation
  const publicKey = crypt.getPublicKey();
  privateKey = crypt.getPrivateKey();
  
  if (!publicKey || !privateKey) {
    throw new Error('Failed to generate cryptographically secure keypair');
  }
  
  // Secure key storage
  privateKey = secureKeyStorage(privateKey);
  
  return publicKey;
}

/**
 * Encrypt the provided plaintext using the destination's public key.
 *
 * @param {string} content - The plaintext message to encrypt.
 * @param {string} publicKey - The public key to use for encryption.
 * @returns {string} The encrypted ciphertext.
 */
function encrypt(content, publicKey) {
  // Validate inputs
  if (typeof content !== 'string' || typeof publicKey !== 'string') {
    throw new Error('Invalid input types for encryption');
  }
  
  // Sanitize and validate content length
  content = content.trim();
  if (content.length > MAX_MESSAGE_LENGTH) {
    throw new Error('Message too large for encryption');
  }
  
  // Sanitize public key
  publicKey = publicKey.trim();
  
  // Validate key and content
  if (!content || !publicKey) {
    throw new Error('Empty content or public key');
  }
  
  try {
    crypt.setKey(publicKey);
    const encrypted = crypt.encrypt(content);
    
    if (!encrypted) {
      throw new Error('Encryption failed');
    }
    
    return encrypted;
  } catch (error) {
    throw new Error('Encryption process failed: ' + error.message);
  }
}

/**
 * Decrypt the provided ciphertext using the stored private key.
 *
 * @param {string} content - The ciphertext to decrypt.
 * @returns {string} The decrypted plaintext.
 */
function decrypt(content) {
  // Validate input
  if (typeof content !== 'string') {
    throw new Error('Invalid input type for decryption');
  }
  
  // Sanitize input
  content = content.trim();
  
  // Check if private key exists
  if (!privateKey) {
    throw new Error('Private key not generated. Please generate keys first.');
  }
  
  try {
    crypt.setKey(privateKey);
    const decrypted = crypt.decrypt(content);
    
    if (!decrypted) {
      throw new Error('Decryption failed');
    }
    
    return decrypted;
  } catch (error) {
    throw new Error('Decryption process failed: ' + error.message);
  }
}