const jwt = require('jsonwebtoken');
const NodeCache = require('node-cache');
const generateEkeyFromUserAndDuration = require('./utils/generateEkeyFromUserAndDuration');
const {encrypt, decrypt} = require('./utils/aes');
const getCoreConfigFromConfig = require('./utils/getCoreConfigFromConfig');
const tokensCache = new NodeCache();
const truthCache = new NodeCache();

// ekey, eproof=encrypt(ekey)

async function handleKeyVerification(ctx, config) {
  const {ekey} = ctx.request.body;
  const {duration} = getCoreConfigFromConfig(config);
  // TODO check how library works, get operation might be blocking
  const token = tokensCache.get(ekey);
  if(token) {
    ctx.ok({token});
    truthCache.set(ekey, true, duration);
  } else {
    ctx.forbidden();
  }
}

async function handleProofVerification(ctx, config) {
  const {eproof} = ctx.request.body;
  const {key} = getCoreConfigFromConfig(config);

  const ekey = decrypt(eproof, key);
  if(ekey && truthCache.get(ekey)) {
    const token = tokensCache.get(ekey);
    ctx.ok({token});
    truthCache.del(ekey);
    tokensCache.del(ekey);
  } else {
    ctx.forbidden();
  }
}

async function handleKeyGeneration(ctx, config, sendKeyPlugin) {
  const {duration, expiresIn, key} = getCoreConfigFromConfig(config);
  const {user, params} = ctx.request.body;
  const ekey = generateEkeyFromUserAndDuration(user, duration);
  const token = jwt.sign({u: user, p: params}, key, {expiresIn});
  const eproof = encrypt(ekey, key);
  tokensCache.set(ekey, token, duration);
  ctx.ok({eproof});
  sendKeyPlugin({user, params, ekey, config});
}

async function handleTokenGeneration(ctx, config) {
  const {ekey, eproof} = ctx.request.body;
  if(ekey) {
    await handleKeyVerification(ctx, config);
  } else if(eproof) {
    await handleProofVerification(ctx, config);
  }
}

async function handleTokenVerification(ctx, config) {
  const {key} = getCoreConfigFromConfig(config);
  const {token} = ctx.params;
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