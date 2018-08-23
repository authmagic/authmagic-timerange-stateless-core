const jwt = require('jsonwebtoken');
const NodeCache = require('node-cache');
const generateEkeyFromUserAndDuration = require('./utils/generateEkeyFromUserAndDuration');
const {encrypt, decrypt} = require('./utils/aes');
const getCoreConfigFromConfig = require('./utils/getCoreConfigFromConfig');
const getRefreshTokenFromTokenAndKey = require('./utils/getRefreshTokenFromTokenAndKey');
const getToken = require('./utils/getToken');
const tokensCache = new NodeCache();
const truthCache = new NodeCache();

// ekey, eproof=encrypt(ekey)

// TODO add validation
async function handleTokenGenerationFromEkey(ctx, config) {
  const {ekey} = ctx.request.body;
  const {duration, key} = getCoreConfigFromConfig(config);
  // TODO check how library works, get operation might be blocking
  const token = tokensCache.get(ekey);
  if(token) {
    const refreshToken = getRefreshTokenFromTokenAndKey(token, key);;
    ctx.ok({token, refreshToken});
    truthCache.set(ekey, true, duration);
  } else {
    ctx.forbidden();
  }
}

async function getKeyFromProof(ctx, config) {
  const {eproof} = ctx.request.body;
  const {key} = getCoreConfigFromConfig(config);
  const ekey = decrypt(eproof, key);
  if(ekey && truthCache.get(ekey)) {
    ctx.ok({ekey});
  } else {
    ctx.forbidden();
  }
}

async function handleTokenGenerationFromRefreshToken(ctx, config) {
  const {token, refreshToken} = ctx.request.body;
  const {key, expiresIn} = getCoreConfigFromConfig(config);
  if(refreshToken === getRefreshTokenFromTokenAndKey(token, key)) {
    jwt.verify(token, key, function(err, decoded) {
      if(err) {
        ctx.forbidden();
      } else {
        const token = getToken(decoded, key, {expiresIn});
        const refreshToken = getRefreshTokenFromTokenAndKey(token, key);
        ctx.ok({token, refreshToken});
      }
    });
  } else {
    ctx.forbidden();
  }
}

async function handleKeyGeneration(ctx, config, sendKeyPlugin) {
  const {duration, expiresIn, key} = getCoreConfigFromConfig(config);
  const {user, redirectUrl, params} = ctx.request.body;
  const ekey = generateEkeyFromUserAndDuration(user, duration);
  const token = getToken({u: user, p: params}, key, {expiresIn});
  const eproof = encrypt(ekey, key);
  tokensCache.set(ekey, token, duration);
  ctx.ok({eproof});
  sendKeyPlugin({user, redirectUrl, params, ekey, config});
}

async function handleTokenGeneration(ctx, config) {
  const {ekey, token, refreshToken, eproof} = ctx.request.body;
  if(ekey) {
    await handleTokenGenerationFromEkey(ctx, config);
  } else if(token && refreshToken) {
    await handleTokenGenerationFromRefreshToken(ctx, config);
  } else if(eproof) {
    await getKeyFromProof(ctx, config);
  } else {
    ctx.forbidden();
  }
}

async function handleTokenVerification(ctx, config) {
  const {key} = getCoreConfigFromConfig(config);
  const {token} = ctx.request.body;
  jwt.verify(token, key, function(err) {
    if (err) {
      ctx.forbidden();
    } else {
      ctx.ok();
    }
  });
}

module.exports = {
  handleTokenGenerationFromEkey,
  getKeyFromProof,
  handleKeyGeneration,
  handleTokenGeneration,
  handleTokenVerification,
};