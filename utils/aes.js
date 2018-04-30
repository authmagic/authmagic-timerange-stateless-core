const crypto = require('crypto');

function encrypt(text, key){
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-128-cbc', key, iv);
  const encrypted = cipher.update(text);
  const finalBuffer = Buffer.concat([encrypted, cipher.final()]);
  return iv.toString('hex') + ':' + finalBuffer.toString('hex');
}
 
function decrypt(text, key){
  if(!text) {
    return null;
  }

  const encryptedArray = text.split(':');
  const iv = new Buffer(encryptedArray[0], 'hex');
  const encrypted = new Buffer(encryptedArray[1], 'hex');
  const decipher = crypto.createDecipheriv('aes-128-cbc', key, iv);
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