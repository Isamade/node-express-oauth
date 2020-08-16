const express = require("express")
const bodyParser = require("body-parser")
const fs = require("fs");
const jwt = require("jsonwebtoken");
const { timeout } = require("./utils")

const config = {
	port: 9002,
	publicKey: fs.readFileSync("assets/public_key.pem"),
}

const users = {
	user1: {
		username: "user1",
		name: "User 1",
		date_of_birth: "7th October 1990",
		weight: 57,
	},
	john: {
		username: "john",
		name: "John Appleseed",
		date_of_birth: "12th September 1998",
		weight: 87,
	},
}

const app = express()
app.use(timeout)
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

/*
Your code here
*/
app.get('/user-info', (req, res) => {
	if(req.headers.authorization){
		let userInfo = null;
		try {
		userInfo = jwt.verify(req.headers.authorization.slice(7), config.publicKey, {algorithm: 'RS256'})
		} catch(e){
			res.status(401).end();
		}
		if(userInfo){
			const user = users[userInfo.userName];
			const userWithRestrictedFields = {};
			const scope = userInfo.scope.split(" ");
			for(let i = 0; i < scope.length; i++){
				const field = scope[i].slice("permission:".length);
				userWithRestrictedFields[field] = user[field];
			}
			res.json(userWithRestrictedFields)
		} else {
			res.status(401).end();
		}
	} else {
		res.status(401).end();
	}
})

const server = app.listen(config.port, "localhost", function () {
	var host = server.address().address
	var port = server.address().port
})

// for testing purposes
module.exports = {
	app,
	server,
}
