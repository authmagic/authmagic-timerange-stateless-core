const jwt = require('jsonwebtoken');
const NodeCache = require('node-cache');
const generateKeyFromUserAndDuration = require('./utils/generateKeyFromUserAndDuration');
const {encrypt, decrypt} = require('./utils/aes');
const tokensCache = new NodeCache();
const truthCache = new NodeCache();

async function handleKeyVerification(ctx, config) {
  const {z} = ctx.request.body;
  const {duration} = config;
  // TODO check how library works, get operation might be blocking
  const token = tokensCache.get(z);
  if(token) {
    ctx.ok({token});
    truthCache.set(z, true, duration);
  } else {
    ctx.forbidden();
  }
}

async function handleProofVerification(ctx, config) {
  const {zp} = ctx.request.body;
  const {key} = config;

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

async function handleKeyGeneration(ctx, config, sendKeyPlugin) {
  const {duration, expiresIn, key} = config;
  const {user, params} = ctx.request.body;
  const z = generateKeyFromUserAndDuration(user, duration);
  const token = jwt.sign({u: user, p: params}, key, {expiresIn});
  const zp = encrypt(z, key);
  tokensCache.set(z, token, duration);
  ctx.ok({zp});
  sendKeyPlugin({user, params, z, config});
}

async function handleTokenGeneration(ctx, config) {
  const {z, zp} = ctx.request.body;
  if(z) {
    await handleKeyVerification(ctx, config);
  } else if(zp) {
    await handleProofVerification(ctx, config);
  }
}

async function handleTokenVerification(ctx, config) {
  const {key} = config;
  const token = ctx.params.token;
  jwt.verify(token, key, function(err) {
    if (err) {
      ctx.forbidden();
    } else {
      ctx.ok();
    }
  });
}

module.exports = {
  handleKeyVerification,
  handleProofVerification,
  handleKeyGeneration,
  handleTokenGeneration,
  handleTokenVerification,
};