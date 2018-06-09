const test = require('ava');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const params = require('./params');
const getToken = require('./utils/getToken');
const sha256 = require('./utils/sha256');
const getRefreshTokenFromTokenAndKey = require('./utils/getRefreshTokenFromTokenAndKey');
const genereateEkeyFromUserAndDuration = require('./utils/generateEkeyFromUserAndDuration');
const { encrypt, decrypt } = require('./utils/aes');

test('should encrypt and decrypt string properly', t => {
  const encryptedString = encrypt('test', params.key);
  const decryptedString = decrypt(encryptedString, params.key);
  t.is(decryptedString, 'test');
})

test('should return token', t => {
  const data = {
    email: 'test@test.com',
  };
  const token = getToken(data, params.key);
  const verifyData = jwt.verify(token, params.key);
  t.is(data.email, verifyData.email);
})

test('should generate ekey', t => {
  const user = {
    email: 'test@test.com',
  };
  genereateEkeyFromUserAndDuration(user, params.duration);
  t.pass();
})

test('should refresh token', t => {
  const data = {
    email: 'test@test.com',
  };
  const token = getToken(data, params.key);
  getRefreshTokenFromTokenAndKey(token, params.key);
  t.pass();
})