const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")
const secrets = require("../auth/secrets.js")
const Users = require("./user-model.js")

module.exports = {
    validateCredentials,
    validateUser,
    restricted
}

function validateUser(req, res, next) {
    if(!req.body.username || !req.body.password) {
        res.status(400).json({
            message: "Enter all fields."
        })
    } else {
        next()
    }
}

function validateCredentials(req, res, next) {
    const credentials = req.body

    Users.findBy(credentials.username)
    .then( user => {
        if (!user || !bcrypt.compareSync(credentials.password, user.password)) {
            return res.status(401).json({ error: "Wrong!" })
        } else {
            req.body.userId = user.id
            next()
        }
    })
    .catch( err => {
        res.status(500).json({ errorMessage: "No one by that name." })
    })
}

function restricted(req, res, next) {   
    try {
        const token = req.headers.authorization.split(" ")[1]
    
        if (token) {
            jwt.verify( token, secrets.jwtSecret, (err, decodedToken) => {
                if (err) {
                    res.status(401).json({ message: "Unauthorized!" })
                } else {
                    req.decodedJwt = decodedToken
                    console.log("Token", req.decodedJwt)
                    next()
                }
            })
        } else {
            throw new Error("Invalid token.")
        }
    } catch (err) {
        res.status(401).json({ error: "You don't have a bearer token!" })
    }
}
