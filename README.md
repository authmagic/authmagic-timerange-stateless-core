authmagic-timerange-stateless-core
========================
Stateless and passwordless authentication core for <a href="https://github.com/authmagic/authmagic">authmagic</a>.

Magic link
-----------
To check the identity of the user it is possible to send to his email, phone or any other resource he owns an authorization link. By clicking on that link user identifies himself as an owner of the resource. You can see many apps who suggest this option, for example <a href="https://medium.com/">medium.com</a> and <a href="https://auth0.com/">auth0.com</a>.
<img src="https://github.com/authmagic/authmagic/blob/master/docs/images/authmagic-timerange-stateless-core.png?raw=true" width="600px"/>

How it looks in the real world:

<img src="https://github.com/authmagic/authmagic/blob/master/docs/images/medium-example1.png?raw=true" width="600px"/>
<img src="https://github.com/authmagic/authmagic/blob/master/docs/images/medium-confirm.png?raw=true" width="600px"/>

Passwordless
-----------
Magic link allows not to have any connection to users list. By that you have an option to build completely isolated authentication service.

Stateless
-----------
Current core is sharing JWT tokens by request what allows not to keep any state data.

API
-----------
Core expects json format of data.

### post /key
Generate ekey and send it to the resource owned by client, like email.

#### Input:
user - object with user description, it will be added to the JWT as an opened information

redirectUrl - string of redirect destination after key generated

params - object with user description, it will be added to the JWT as an opened information

#### Output:
eproof - encrypted version of ekey which could be used to get the token if ekey was activated

### post /token
Generate JWT token from key. Token could be generated in 3 different scenarios: from ekay, from eproof, from token + refreshToken

#### Input:
ekey - code sent to resource own by client, like email

eproof - encrypted version of ekey which could be used to get the token if ekey was activated

token - valid token

refreshToken - valid refresh token

#### Output:
token - valid updated token

### get /token/status/:token
Checks the status of the token provided.

Main idea
-----------
Next few lines of code show main objects used in the core.
```
const ekey = generateEkeyFromUserAndDuration(user, duration);
const token = getToken({u: user, p: params}, key, {expiresIn});
const eproof = encrypt(ekey, key);
```

Configuration
-----------
Core could be configured using next params, they are reflected in the configuration file:

duration - in seconds, duration of the ekey's validity

key - secret key which will be used for encryption, it ensures a security of whole solution

sendKeyPlugin - name of the plugin which will be used to send ekey

expiresIn - in seconds, duration of the token's validity

Plugins
-----------
In this core plugin is used to send a message with ekey.
```
sendKeyPlugin({user, redirectUrl, params, ekey, config});
```
So plugin is a function with arguments you see above.
See existining plugins for real examples: <a href="https://github.com/authmagic/authmagic-email-plugin">authmagic-email-plugin</a>, <a href="https://github.com/authmagic/authmagic-proxy-plugin">authmagic-proxy-plugin</a>, <a href="https://github.com/authmagic/authmagic-smsc-plugin">authmagic-smsc-plugin</a>.
