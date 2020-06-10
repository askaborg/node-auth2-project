const express = require("express")
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")
const secrets = require("../auth/secrets.js")
const Users = require("./user-model.js")
const uMid = require("./userMiddleware.js")
const router = express.Router()

router.post("/register", uMid.validateUser, (req, res) => {
    const credentials = req.body
    const hash = bcrypt.hashSync(credentials.password, 12)
    credentials.password = hash
    
    Users.insert(credentials)
    .then( id => {
        res.status(201).json({id: id[0], ...credentials})
    })
    .catch( err => {
        res.status(500).json({
            errorMessage: "Unable to create."
        })
    })
})

router.post("/login", uMid.validateUser, uMid.validateCredentials, (req, res) => {
    let { username, password } = req.body

    Users.findBy(username)
    .then(user => {
      if (user && bcrypt.compareSync(password, user.password)) {
        const token = generateToken(user)

        res.status(200).json({
          message: `Hello ${user.username}! Here's the token.`, token
        })
      } else {
        res.status(401).json({ message: "You shall not pass!" })
      }
    })
    .catch(error => {
      res.status(500).json(error)
    })
})

function generateToken(user) {
  const payload = {
    subject: user.id,
    username: user.username
  }
  const options = { expiresIn: "1d" }

  return jwt.sign(payload, secrets.jwtSecret, options)
}

router.get("/users", uMid.restricted, (req, res) => {
    Users.find()
    .then( users => {
        res.status(200).json(users)
    })
    .catch( err => {
        res.status(500).json({
            errorMessage: "Unable to get users."
        })
    })
})

module.exports = router