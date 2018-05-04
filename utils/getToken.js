const _ = require('lodash');
const jwt = require('jsonwebtoken');

module.exports = function getToken(data, key, options) {
  return jwt.sign(_.omit(data, ['iat', 'exp']), key, options);
};