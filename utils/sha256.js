const crypto = require('crypto');

module.exports = function(data) {
  return crypto.createHash('sha256').update(data).digest('base64');
};