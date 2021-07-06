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
  isRateLimiterEnabled: true,
  rateLimiterBlockDurationSeconds: 1800,
  rateLimiterPoints: 3,
  rateLimiterDuration: 600,
};
