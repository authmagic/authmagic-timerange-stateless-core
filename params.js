const crypto = require('crypto');

module.exports = {
  key: process.env.KEY || crypto.randomBytes(8).toString('hex'),
  sendKeyPlugin: "authmagic-email-plugin",
  expiresIn: "20m",
  refreshExpiresIn: "2d",
  securityKeyRule: {
    length: 6,
    charset: "numeric",
  },
  // for debugging and app validations
  // username: securityCode
  fixedSecurityCodes: {
  },
  rateLimiterConfig: {
    '/key': {
      isRateLimiterEnabled: true,
      blockDuration: 1800,
      points: 3,
      duration: 600,
    },
  },
};
