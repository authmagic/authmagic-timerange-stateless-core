const path = require('path');
const {handleKeyGeneration, handleTokenGeneration, handleTokenVerification} = require('./routes');
const getCoreConfigFromConfig = require('./utils/getCoreConfigFromConfig');

module.exports = function(router, config) {
  const {key, sendKeyPlugin: sendKeyPluginName} = getCoreConfigFromConfig(config);
  if(!sendKeyPluginName) {
    console.log('sendKeyPlugin plugin is undefined');
    process.exit(-1);
  }

  const sendKeyPlugin = require(path.resolve(`./node_modules/${sendKeyPluginName}/plugin`));
  router.post('/key', (ctx) => handleKeyGeneration(ctx, config, sendKeyPlugin));
  router.post('/token', (ctx) => handleTokenGeneration(ctx, config));
  router.get('/token/status/:token', (ctx) => handleTokenVerification(ctx, config));
  return router.routes();
};