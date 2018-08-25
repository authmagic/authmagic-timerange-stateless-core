const path = require('path');
const _ = require('lodash');
const jwt = require('jsonwebtoken');
const generateRandomString = require('randomstring').generate;
const getCoreConfigFromConfig = require('./utils/getCoreConfigFromConfig');
const {encrypt, decrypt} = require('./utils/aes');
const getToken = (data, key, options) => jwt.sign(_.omit(data, ['iat', 'exp']), key, options);
const getRefreshToken = (token, key, options) => jwt.sign({signature: jwt.decode(token, {complete: true}).signature}, key, options);
const checkRefreshToken = (token, refreshToken, key) => {
  try {
    if(jwt.verify(token, key) && jwt.verify(refreshToken, key)) {
      return jwt.decode(token, {complete: true}).signature === jwt.decode(refreshToken).signature;
    }
  } catch(e) {
    return false;
  }

  return false;
};
const wrapKey = (securityKey, key) => securityKey + key.substr(0, key.length - securityKey.toString().length);

// TODO add validation for every route
// TODO add brute checker https://github.com/llambda/koa-brute
// TODO add rate-limit
// TODO add eslint-plugin-security
// TODO add helmet
// TODO add tests
// TODO add scan with npm audit, nsp and snyk
// TODO blacklist tokens
module.exports = function(router, config) {
  const {key, expiresIn, refreshExpiresIn, securityKeyRule, sendKeyPlugin: sendKeyPluginName} = getCoreConfigFromConfig(config);
  if(!sendKeyPluginName) {
    console.log('sendKeyPlugin plugin is undefined');
    process.exit(-1);
  }

  const sendKeyPlugin = require(path.resolve(`./node_modules/${sendKeyPluginName}/plugin`));

  router.post('/key', async function handleKeyGeneration(ctx) {
    const {user, redirectUrl, params} = ctx.request.body;
    const token = getToken({u: user, p: params}, key, {expiresIn});
    const ekey = encrypt(token, key);
    const securityKey = generateRandomString(securityKeyRule);
    const eproof = encrypt(ekey, wrapKey(securityKey, key));
    ctx.ok({eproof});
    sendKeyPlugin({user, redirectUrl, params, ekey, securityKey, config});
  });

  router.post('/token/status', async function handleTokenVerification(ctx) {
    const {token} = ctx.request.body;
    jwt.verify(token, key, function(err) {
      if (err) {
        const {name, message} = err;
        ctx.forbidden({name, message});
      } else {
        ctx.ok();
      }
    });
  });

  router.post('/token', async function handleTokenGeneration(ctx) {
    async function generateTokenFromEkey(ctx) {
      const {ekey} = ctx.request.body;
      const token = decrypt(ekey, key);
      if(token) {
        const refreshToken = getRefreshToken(token, key, {expiresIn: refreshExpiresIn});
        ctx.ok({token, refreshToken});
      } else {
        ctx.forbidden();
      }
    }

    async function generateTokenFromRefreshToken(ctx) {
      const {token, refreshToken} = ctx.request.body;
      if(checkRefreshToken(token, refreshToken, key)) {
        jwt.verify(token, key, function(err, decoded) {
          if(err) {
            ctx.forbidden();
          } else {
            const token = getToken(decoded, key, {expiresIn});
            const refreshToken = getRefreshToken(token, key, {expiresIn: refreshExpiresIn});
            ctx.ok({token, refreshToken});
          }
        });
      } else {
        ctx.forbidden();
      }
    }

    async function generateTokenFromProof(ctx) {
      const {eproof, securityKey} = ctx.request.body;
      const ekey = decrypt(eproof, wrapKey(securityKey, key));
      if(ekey) {
        const token = decrypt(ekey, key);
        const refreshToken = getRefreshToken(token, key, {expiresIn: refreshExpiresIn});
        ctx.ok({token, refreshToken});
      } else {
        ctx.forbidden();
      }
    }

    const {ekey, token, refreshToken, eproof, securityKey} = ctx.request.body;
    if(ekey) {
      await generateTokenFromEkey(ctx);
    } else if(token && refreshToken) {
      await generateTokenFromRefreshToken(ctx);
    } else if(eproof && securityKey) {
      await generateTokenFromProof(ctx);
    } else {
      ctx.forbidden();
    }
  });

  return router.routes();
};