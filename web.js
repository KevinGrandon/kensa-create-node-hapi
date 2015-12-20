var crypto = require('crypto')
var fs = require('fs')

var Hapi = require('hapi')

var port = process.env.PORT || 4567
const server = new Hapi.Server()
server.connection({ port: port })

var resources = []

function get_resource (id) {
  id = parseInt(id, 10)
  for (var i in resources) {
    if (resources[i].id === id) {
      return resources[i]
    }
  }
}

function destroy_resource (id) {
  id = parseInt(id, 10)
  for (var i in resources) {
    if (resources[i].id === id) {
      delete resources[i]
    }
  }
}

const basicScheme = function (server, options) {
  return {
    // add headers to the response.
    response: function (request, reply) {
      request.response.header('heroku-nav-data', request.query['nav-data'])
      reply.continue()
    },

    authenticate: function (request, reply) {
      console.log('doing basic authenticate')
      if (request.headers.authorization && request.headers.authorization.search('Basic ') === 0) {
        // fetch login and password
        var usernameAndPass = new Buffer(request.headers.authorization.split(' ')[1], 'base64').toString()
        if (usernameAndPass === process.env.HEROKU_USERNAME + ':' + process.env.HEROKU_PASSWORD) {
          console.log('success, replying')
          return reply.continue({credentials: {username: usernameAndPass}})
        }
      }
      console.log('Unable to authenticate user')
      console.log(request.headers.authorization)
      return reply('Authentication required').code(401)
    }
  }
}

server.auth.scheme('basic', basicScheme)
server.auth.strategy('basic', 'basic')

const ssoScheme = function (server, options) {
  return {
    // Skip authenticate because it does not yet have the necessary payload.
    // We'll authenticate the user in the `payload` method.
    authenticate: function (request, reply) {
      console.log('in authenticate()')
      return reply.continue({credentials: {}})
    },

    payload: function (request, reply) {
      console.log('doing sso authenticate')
      var id = request.payload.id
      console.log(id)
      console.log('payload: ', request.payload)
      var pre_token = id + ':' + process.env.SSO_SALT + ':' + request.query.timestamp
      var shasum = crypto.createHash('sha1')
      shasum.update(pre_token)
      var token = shasum.digest('hex')
      if (request.query.token !== token) {
        return reply(Hapi.boom.unauthorized('Token Mismatch')).code(403)
      }
      var time = (new Date().getTime() / 1000) - (2 * 60)
      if (parseInt(request.query.timestamp, 10) < time) {
        return reply(Hapi.boom.unauthorized('Timestamp Expired')).code(403)
      }
      request.auth.credentials = {
        credentials: {resource: get_resource(id), email: request.payload.email},
        herokuNavData: request.payload['nav-data']
      }
      return reply.continue()
    }
  }
}

server.auth.scheme('sso', ssoScheme)
server.auth.strategy('sso', 'sso')

// Allow setting of the cookie for heroku.
server.state('heroku-nav-data', {
  ttl: null,
  isSecure: false,
  isHttpOnly: true,
  encoding: 'none',
  clearInvalid: false,
  strictHeader: false
})

// Provision
server.route({
  method: 'POST',
  path: '/heroku/resources',
  config: {
    auth: 'basic',
    handler: function (request, reply) {
      console.log(request.payload)
      var resource = {id: resources.length + 1, plan: request.payload.plan}
      resources.push(resource)
      reply(resource)
    }
  }
})

// Plan Change
server.route({
  method: 'PUT',
  path: '/heroku/resources/:id',
  config: {
    auth: 'basic',
    handler: function (request, reply) {
      console.log(request.payload)
      console.log(request.params)
      var resource = get_resource(request.params.id)
      if (!resource) {
        reply('Not found.').code(404)
        return
      }
      resource.plan = request.payload.plan
      reply('ok')
    }
  }
})

// Deprovision
server.route({
  method: 'DELETE',
  path: '/heroku/resources/:id',
  config: {
    auth: 'basic',
    handler: function (request, reply) {
      console.log(request.params)
      if (!get_resource(request.params.id)) {
        reply('Not found', 404)
        return
      }
      destroy_resource(request.params.id)
      reply('ok')
    }
  }
})

// GET SSO
server.route({
  method: 'GET',
  path: '/heroku/resources/:id',
  config: {
    auth: 'sso',
    handler: function (request, reply) {
      reply()
        .state('heroku-nav-data', request.payload['nav-data'])
        .redirect('/')
    }
  }
})

// POST SSO
server.route({
  method: 'POST',
  path: '/sso/login',
  config: {
    auth: 'sso',
    handler: function (request, reply) {
      reply()
        .state('heroku-nav-data', request.payload['nav-data'])
        .redirect('/')
    }
  }
})

// SSO LANDING PAGE
server.route({
  method: 'GET',
  path: '/',
  config: {
    handler: function (request, reply) {
      if (request.auth.credentials.resource) {
        reply('index.html', {layout: false,
          resource: request.auth.credentials.resource, email: request.auth.credentials.email })
      } else {
        reply('Not found.').code(404)
      }
    }
  }
})

server.start(() => {
  console.log('Server running at:', server.info.uri)
})
