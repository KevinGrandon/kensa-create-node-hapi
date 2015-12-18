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

function basic_auth (req, reply) {
  if (req.headers.authorization && req.headers.authorization.search('Basic ') === 0) {
    // fetch login and password
    console.log('heroku stuff: ', process.env.HEROKU_USERNAME + ':' + process.env.HEROKU_PASSWORD)
    if (new Buffer(req.headers.authorization.split(' ')[1], 'base64').toString() === process.env.HEROKU_USERNAME + ':' + process.env.HEROKU_PASSWORD) {
      return
    }
  }
  console.log('Unable to authenticate user')
  console.log(req.headers.authorization)
  reply('Authentication required')
    .header('WWW-Authenticate', 'Basic realm="Admin Area"')
    .code(401)
  throw new Error('Unable to authenticate')
}

function sso_auth (req, reply) {
  var id = req.query.id || req.params.id
  console.log(id)
  console.log('params: ', req.params)
  console.log('query: ', req.query)
  var pre_token = id + ':' + process.env.SSO_SALT + ':' + req.query.timestamp
  var shasum = crypto.createHash('sha1')
  shasum.update(pre_token)
  var token = shasum.digest('hex')
  if (req.query.token !== token) {
    reply('Token Mismatch').code(403)
    throw new Error('Token Mismatch')
  }
  var time = (new Date().getTime() / 1000) - (2 * 60)
  if (parseInt(req.query.timestamp, 10) < time) {
    reply('Timestamp Expired').code(403)
    throw new Error('timestamp expired')
  }
  reply().state('heroku-nav-data', req.query['nav-data']).hold()
  req.session.resource = get_resource(id)
  req.session.email = req.query.email
}

// Provision
server.route({
  method: 'POST',
  path: '/heroku/resources',
  handler: function (request, reply) {
    basic_auth(request, reply)
    console.log(request.payload)
    var resource = {id: resources.length + 1, plan: request.payload.plan}
    resources.push(resource)
    reply(resource)
  }
})

// Plan Change
server.route({
  method: 'PUT',
  path: '/heroku/resources/:id',
  handler: function (request, reply) {
    basic_auth(request, reply)
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
})

// Deprovision
server.route({
  method: 'DELETE',
  path: '/heroku/resources/:id',
  handler: function (request, reply) {
    basic_auth(request, reply)
    console.log(request.params)
    if (!get_resource(request.params.id)) {
      reply('Not found', 404)
      return
    }
    destroy_resource(request.params.id)
    reply('ok')
  }
})

// GET SSO
server.route({
  method: 'GET',
  path: '/heroku/resources/:id',
  handler: function (request, reply) {
    sso_auth(request, reply)
    reply.redirect('/')
  }
})

// POST SSO
server.route({
  method: 'POST',
  path: '/sso/login',
  handler: function (request, reply) {
    sso_auth(request, reply)
    reply.redirect('/')
  }
})

// SSO LANDING PAGE
server.route({
  method: 'GET',
  path: '/',
  handler: function (request, reply) {
    if (request.session.resource) {
      reply('index.html', {layout: false,
        resource: request.session.resource, email: request.session.email })
    } else {
      reply('Not found.').code(404)
    }
  }
})

server.start(() => {
  console.log('Server running at:', server.info.uri)
})
