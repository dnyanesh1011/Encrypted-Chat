'use strict';

// Ensure self.window is defined for SJCL compatibility
self.window = self;

// Import the SJCL library with ECC module enabled (using HTTPS)
self.importScripts('https://cdn.patricktriest.com/vendor/sjcl/sjcl.min.js');

let keypair = null;

// Listen for messages from the UI thread
self.addEventListener('message', (event) => {
  const data = event.data;

  // Validate the incoming message format
  if (!Array.isArray(data) || data.length < 1) {
    console.error('Invalid message format');
    postMessage(['error', 'Invalid message format']);
    return;
  }

  // Destructure expected parameters from the message
  const [messageType, text, key] = data;
  let result;

  try {
    switch (messageType) {
      case 'generate-keys':
        result = generateKeypair();
        break;
      case 'encrypt':
        if (!text || !key) {
          throw new Error('Missing parameters for encryption');
        }
        result = encrypt(text, key);
        break;
      case 'decrypt':
        if (!text) {
          throw new Error('Missing parameter for decryption');
        }
        result = decrypt(text);
        break;
      default:
        throw new Error(`Unknown message type: ${messageType}`);
    }
  } catch (error) {
    // Return error back to the UI thread
    postMessage(['error', error.message]);
    return;
  }

  // Return the result along with the message type
  postMessage([messageType, result]);
});

/** Generate and store the keypair */
function generateKeypair() {
  keypair = sjcl.ecc.elGamal.generateKeys(256);

  // Return only the public key; keep the private key hidden
  return serializePublicKey(keypair.pub.get());
}

/** Encrypt the provided string with the destination's public key */
function encrypt(content, publicKeyString) {
  const publicKey = unserializePublicKey(publicKeyString);
  return sjcl.encrypt(publicKey, content);
}

/** Decrypt the provided string with the local private key */
function decrypt(content) {
  if (!keypair || !keypair.sec) {
    throw new Error('Keypair not generated. Generate keys first.');
  }
  return sjcl.decrypt(keypair.sec, content);
}

/** Convert the public key to a base64 string */
function serializePublicKey(key) {
  return sjcl.codec.base64.fromBits(key.x.concat(key.y));
}

/** Convert a base64 string to a public key object */
function unserializePublicKey(keyStr) {
  const keyBits = sjcl.codec.base64.toBits(keyStr);
  return new sjcl.ecc.elGamal.publicKey(sjcl.ecc.curves.c256, keyBits);
}
