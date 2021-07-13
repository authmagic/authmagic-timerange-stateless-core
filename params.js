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
    '/key': [
      {
        isRateLimiterEnabled: true,
        key: ['ip'],
        limiterOptions: {
          duration: 600,
          points: 10,
          blockDuration: 1800,
        },
        getErrorDescription: ({ ip }) => `Too Many Requests for ${ip}.`,
      },
    ],
  },
};
