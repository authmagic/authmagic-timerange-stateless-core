const {encrypt} = require('./aes');
const sha256 = require('./sha256');

module.exports = function getRefreshTokenFromTokenAndKey(token, key) {
  return sha256(encrypt(token, key, 'aes-128-ecb'));
};