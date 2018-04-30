const sha256 = require('./sha256');

module.exports = function generateEkeyFromUserAndDuration(user, duration) {
  const timestamp = Math.floor(new Date().getTime()/1000);
  const i = Math.floor(timestamp/duration);
  const mi = duration*i;
  const mi1 = duration*(i+1);
  const ni = duration*i - duration/2;
  const ni1 = duration*(i+1) - duration/2;
  if(timestamp >= mi && ni1 > timestamp) {
    return sha256(user + mi + mi1);
  } else if(timestamp >= ni1 && timestamp <= mi1) {
    return sha256(user + ni + ni1);
  }

  return null;
};