'use strict'

const crypto = require('crypto')
const axios = require('axios').default;

const allowList = []

module.exports = function (config, stuff) {
  stuff.logger.info('Configuring verdaccio-static-token');

  (config || []).forEach(_ => { allowList.push(_.user || _) })

  return {
    authenticate: function (user, password, callback) {
      if (allowList.includes(user)) {
        stuff.logger.warn(`Allowing access to: ${user}`)
        callback(null, [user])
        return
      }

      // do nothing: go to next auth plugin configured
      callback(null, null)
    },
    register_middlewares: function (app, authInstance, storageInstance) {
      console.log('middy register_middlewares')

      // RFC6750 says Bearer must be case sensitive
      const accessTokens = new Map((config || [])
        .map(_ => `Bearer ${_.token}`)
        .map((authHeader, i) => [authHeader, config[i]]))

      const verdaccioSecret = storageInstance.config.secret

      app.use(async function(req, res, next) {
        try {
          const overwrite = accessTokens.get(req.headers.authorization);

          console.log('overwrite: ', overwrite);

          if (overwrite) {
            const auth = buildAesAuthToken(overwrite.user, overwrite.password);
            console.log('overwrite auth: ', auth);
            req.headers.authorization = auth;
          } else {
            const token = (req.headers.authorization || '').split('Bearer ')[1];
            console.log('token: ', token);
  
            if (token) {

              const { endpoint_url } = stuff.config;
              const response = await axios.post(endpoint_url, { token });
              console.log('response status: ', response.status);
  
              if (response.status === 200) {
                stuff.logger.warn('Applying custom token')
                const { user, password } = accessTokens.values().next().value || {};
                console.log('user: ', user)
                console.log('password: ', password)
                const auth = buildAesAuthToken(user || '', password || '');
                console.log('auth: ', auth);
                req.headers.authorization = auth;
              }
            }
          }
        } catch(err) {
          console.log('error msg: ', err);
          console.log('error stack: ', err.stack);
          console.log('error cause: ', err.cause);
        }

        next();
      })

      function buildAesAuthToken (user, password) {
        // I can't use createCipheriv since Verdaccio 3.x use createDecipher
        const cipher = crypto.createCipher('aes192', verdaccioSecret) // eslint-disable-line node/no-deprecated-api
        const part = cipher.update(Buffer.from(`${user}:${password}`, 'utf8'))
        const encripted = Buffer.concat([part, cipher.final()])
        return `Bearer ${encripted.toString('base64')}`
      }
    }
  }
}
