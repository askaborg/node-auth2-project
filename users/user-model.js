const db = require('../data/db-config.js')

module.exports = {
  find,
  findBy,
  insert
}

function find() {
  return db('users')
}

function findBy(username) {
  return db('users').where({ username }).first()
}

function insert(user) {
  return db('users').insert(user)
}