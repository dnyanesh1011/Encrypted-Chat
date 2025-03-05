'use strict';

// Ensure self.window is defined for SJCL compatibility
self.window = self; // Required for the sjcl library to work within the webworker

// Import the SJCL library using a secure URL
self.importScripts('https://bitwiseshiftleft.github.io/sjcl/sjcl.js');

// Listen for messages from the UI thread
self.addEventListener('message', (event) => {
  const { data } = event;
  
  // Validate the incoming message format
  if (!Array.isArray(data) || data.length < 3) {
    console.error('Invalid message data format');
    postMessage(['error', 'Invalid message data format']);
    return;
  }
  
  const [messageType, text, secret] = data;
  let result;
  
  try {
    switch (messageType) {
      case 'encrypt':
        result = encrypt(text, secret);
        break;
      case 'decrypt':
        result = decrypt(text, secret);
        break;
      default:
        throw new Error(`Unknown message type: ${messageType}`);
    }
  } catch (error) {
    // Send error back to the UI thread
    postMessage(['error', error.message]);
    return;
  }
  
  // Return the result along with the message type
  postMessage([messageType, result]);
});

/** Encrypt the provided string with the shared secret */
function encrypt(content, secret) {
  return sjcl.encrypt(secret, content, { ks: 256 });
}

/** Decrypt the provided string with the shared secret */
function decrypt(content, secret) {
  return sjcl.decrypt(secret, content, { ks: 256 });
}
