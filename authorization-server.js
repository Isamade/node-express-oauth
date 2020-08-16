const fs = require("fs");
const path = require ('path');
const express = require("express");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const {
	randomString,
	containsAll,
	decodeAuthCredentials,
	timeout,
} = require("./utils");

const config = {
	port: 9001,
	privateKey: fs.readFileSync("assets/private_key.pem", 'utf8'),

	clientId: "my-client",
	clientSecret: "zETqHgl0d7ThysUqPnaFuLOmG1E=",
	redirectUri: "http://localhost:9000/callback",

	authorizationEndpoint: "http://localhost:9001/authorize",
}

const clients = {
	"my-client": {
		name: "Sample Client",
		clientSecret: "zETqHgl0d7ThysUqPnaFuLOmG1E=",
		scopes: ["permission:name", "permission:date_of_birth"],
	},
	"test-client": {
		name: "Test Client",
		clientSecret: "TestSecret",
		scopes: ["permission:name"],
	},
}

const users = {
	user1: "password1",
	john: "appleseed",
}

const requests = {}
const authorizationCodes = {}

let state = "";

const app = express();
app.set("view engine", "ejs");
app.set("views", "assets/authorization-server");
app.use(timeout);
app.use(express.static(path.join(__dirname, 'assets/authorization-server')));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

/*
Your code here
*/
app.get('/authorize', (req, res) => {
	let randomResult = randomString();
	requests[randomResult] = req.query;
	if(clients[req.query.client_id]){
		if(containsAll(clients[req.query.client_id].scopes, req.query.scope.split(" "))){
			res.status(200).render('login', {client: clients[req.query.client_id], scope: req.query.scope, requestId: randomResult});
		} else {
			res.status(401).end();
		}
	} else {
		res.status(401).end();
	}
});

app.post('/approve', (req, res) => {
	let randomResult2 = randomString();
	if(users[req.body.userName] === req.body.password){
		if(requests[req.body.requestId]){
			let clientRequest = requests[req.body.requestId];
			delete requests[req.body.requestId];
			authorizationCodes[randomResult2] = {clientReq: clientRequest, userName: req.body.userName};
			res.redirect(`${clientRequest.redirect_uri}?code=${encodeURIComponent(randomResult2)}&state=${clientRequest.state}`);			
		} else {
		res.status(401).end();
		}
	} else {
	res.status(401).end();
	}
});
app.post('/token', (req, res) => {
	if(req.headers.authorization){
		let {clientId, clientSecret} = decodeAuthCredentials(req.headers.authorization);
		if(clients[clientId].clientSecret === clientSecret && authorizationCodes[req.body.code]){
			let obj = authorizationCodes[req.body.code];
			delete authorizationCodes[req.body.code];
			let keyData = config.privateKey;
			jwt.sign({userName: obj.userName, scope: obj.clientReq.scope}, keyData, { algorithm: 'RS256' }, function(err, token) {
				if (err) throw (err);				
				res.json(JSON.stringify({access_token: token, token_type: "Bearer"}));
			})
		} else {
			res.status(401).end();
		}
	} else {
		res.status(401).end();
	}
});

const server = app.listen(config.port, "localhost", function () {
	var host = server.address().address
	var port = server.address().port
});

// for testing purposes

module.exports = { app, requests, authorizationCodes, server }
