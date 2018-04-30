const path = require('path');
const jwt = require('jsonwebtoken');
const NodeCache = require('node-cache');
const {encrypt, decrypt} = require('./utils/aes');
const sha256 = require('./utils/sha256');
const tokensCache = new NodeCache();
const truthCache = new NodeCache();

module.exports = function(router, config) {
  const {duration, key, expiresIn, sendKeyPlugin: sendKeyPluginName} = config;
  if(!sendKeyPluginName) {
    console.log('sendKeyPlugin plugin is undefined');
    process.exit(-1);
  }
  const sendKeyPlugin = require(path.resolve(`./node_modules/${sendKeyPluginName}/plugin`));

  router.post('/key', async function createKey(ctx) {
    const {user, params} = ctx.request.body;
    const timestamp = Math.floor(new Date().getTime()/1000);
    const i = Math.floor(timestamp/duration);
    const mi = duration*i;
    const mi1 = duration*(i+1);
    const ni = duration*i - duration/2;
    const ni1 = duration*(i+1) - duration/2;
    let z = null;
    if(timestamp >= mi && ni1 > timestamp) {
      z = sha256(user + mi + mi1);
    } else if(timestamp >= ni1 && timestamp <= mi1) {
      z = sha256(user + ni + ni1);
    } else {
      throw Error('undefined timestamp');
    }

    const token = jwt.sign({u: user, p: params}, key, {expiresIn});
    const zp = encrypt(z, key);
    tokensCache.set(z, token, duration);
    ctx.ok({zp});
    // TODO queue system may me useful here
    // TODO params may define plugins we need, in some cases - email, in another - sms
    sendKeyPlugin({user, params, z, config});
  });

  router.post('/token', async function getToken(ctx) {
    const {z, zp} = ctx.request.body;
    // z - key to get token
    // zp - encrypted z, to check if z is verified
    if(z) {
      // TODO check how library works, get operation might be blocking
      const token = tokensCache.get(z);
      if(token) {
        ctx.ok({token});
        truthCache.set(z, true, duration);
      } else {
        ctx.forbidden();
      }
    } else if(zp) {
      const z = decrypt(zp, key);
      if(z && truthCache.get(z)) {
        const token = tokensCache.get(z);
        ctx.ok({token});
        truthCache.del(z);
        tokensCache.del(z);
      } else {
        ctx.forbidden();
      }
    }
  });

  router.get('/token/status/:token', async function getTokenStatus(ctx) {
    const token = ctx.params.token;
    jwt.verify(token, key, function(err) {
      if (err) {
        ctx.forbidden();
      } else {
        ctx.ok();
      }
    });
  });

  return router.routes();
};