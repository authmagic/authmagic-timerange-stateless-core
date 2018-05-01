const crypto = require('crypto');

module.exports = {
  "duration": 300,
  "key": process.env.KEY || crypto.randomBytes(8).toString('hex'),
  "sendKeyPlugin": "authmagic-email-plugin",
  "expiresIn": 1200
};