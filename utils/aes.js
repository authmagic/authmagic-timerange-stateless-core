const crypto = require('crypto');

function checkMode(actual, expected) {
  return actual.toLowerCase() === expected.toLowerCase();
}

function encrypt(text, key, mode = 'aes-128-cbc') {
  const iv = checkMode(mode, 'aes-128-ecb') ? Buffer.alloc(0) : crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(mode, key, iv);
  const encrypted = cipher.update(text);
  const finalBuffer = Buffer.concat([encrypted, cipher.final()]);
  if(checkMode(mode, 'aes-128-ecb')) {
    return finalBuffer.toString('hex');
  }

  return iv.toString('hex') + ':' + finalBuffer.toString('hex');
}
 
function decrypt(text, key, mode = 'aes-128-cbc') {
  if(!text) {
    return null;
  }

  const arrText = text.split(':');
  const iv = arrText.length === 1 ? Buffer.alloc(0) : new Buffer(arrText[0], 'hex');
  const encrypted = new Buffer(arrText.pop(), 'hex');
  const decipher = crypto.createDecipheriv(mode, key, iv);
  const decrypted = decipher.update(encrypted);
  try {
    return Buffer.concat([decrypted, decipher.final()]).toString();
  } catch(e) {
    return null;
  }
}

module.exports = {
  encrypt,
  decrypt,
};