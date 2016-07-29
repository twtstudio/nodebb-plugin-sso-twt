(function (module) {
  'use strict'

  var User = module.parent.require('./user')
  var db = module.parent.require('../src/database')
  var passport = module.parent.require('passport')
  var nconf = module.parent.require('nconf')
  var winston = module.parent.require('winston')
  var async = module.parent.require('async')
  var CustomStrategy = module.require('passport-custom')
  var TwTApi = module.require('twt-sso')

  var authenticationController = module.parent.require('./controllers/authentication')

  var constants = Object.freeze(require('./config.json'))
  var configOk = false
  var TwTSSO = {}

  if (!constants.id || !constants.key) {
    winston.error('[sso-twt] App ID and key required.')
  } else {
    configOk = true
  }

  TwTSSO.getStrategy = function (strategies, callback) {
    if (configOk) {
      var twtApi = new TwTApi(constants.id, constants.key, !!constants.https)
      passport.use('twt', new CustomStrategy(function (req, done) {
        if (!req.query || !req.query.token) {
          return this.redirect(twtApi.getLoginUrl(nconf.get('url') + '/auth/twt/callback'))
        }

        twtApi.getUserInfo(req.query.token, function (err, data) {
          if (err) return done(err)
          if (!data.status) return done(data.message)

          TwTSSO.login({
            id: data.result.id,
            handle: data.result.twt_name,
            email: data.result.email
          }, function (err, user) {
            if (err) return done(err)

            authenticationController.onSuccessfulLogin(req, user.uid)
            done(null, user)
          })
        })
      }))

      strategies.push({
        name: 'twt',
        url: '/auth/twt',
        callbackURL: '/auth/twt/callback',
        icon: 'fa-check-square',
        scope: ''
      })

      callback(null, strategies)
    } else {
      callback(new Error('TwT Api Configuration is invalid'))
    }
  }

  TwTSSO.login = function (payload, callback) {
    TwTSSO.getUidByTwTid(payload.id, function (err, uid) {
      if (err) return callback(err)

      if (uid !== null) {
        // Existing User
        callback(null, { uid })
      } else {
        // New User
        var success = function (uid) {
          // Save provider-specific information to the user
          User.setUserField(uid, 'twtId', payload.oAuthid)
          db.setObjectField('twtId:uid', payload.oAuthid, uid)
          callback(null, { uid })
        }

        User.getUidByEmail(payload.email, function (err, uid) {
          if (err) return callback(err)

          if (!uid) {
            User.create({
              username: payload.handle,
              email: payload.email
            }, function (err, uid) {
              if (err) return callback(err)
              success(uid)
            })
          } else {
            success(uid) // Existing account -- merge
          }
        })
      }
    })
  }

  TwTSSO.getUidByTwTid = function (TwTid, callback) {
    db.getObjectField('twtId:uid', TwTid, function (err, uid) {
      if (err) {
        return callback(err)
      }
      callback(null, uid)
    })
  }

  TwTSSO.deleteUserData = function (uid, callback) {
    async.waterfall([
      async.apply(User.getUserField, uid, 'twtId'),
      function (TwTIdToDelete, next) {
        db.deleteObjectField('twtId:uid', TwTIdToDelete, next)
      }
    ], function (err) {
      if (err) {
        winston.error('[sso-twt] Could not remove TwTId data for uid ' + uid + '. Error: ' + err)
        return callback(err)
      }
      callback(null, uid)
    })
  }

  module.exports = TwTSSO
}(module))
