/*

A simple example of how to sign a JWT with an Openid request.

1. A websocket is established with a unique sesssion id
2. The JWS is created and send to the handlebars in the form of a QR code
3. When the user clicks Sign in the QR code is revealed.
4. User scans QR with App
5. User decides what to share
6. JWS is created and posted to client_id

*/

const express = require('express');
const app = express();
const handlebars = require('express-handlebars');
const session = require('express-session');
const QRCode = require('qrcode');
const fs = require('fs');
const bodyParser = require('body-parser');
const server = require('http').Server(app);
const io = require('socket.io')(server);
const cors = require('cors');
var clients = {}; // Keep track of outstanding connections
const base64url = require('base64url');
const jose = require('jose');
// need this?

const {
    JWE,   // JSON Web Encryption (JWE)
    JWK,   // JSON Web Key (JWK)
    JWKS,  // JSON Web Key Set (JWKS)
    JWS,   // JSON Web Signature (JWS)
    JWT,   // JSON Web Token (JWT)
    errors // errors utilized by jose
  } = jose;

const port = 4567;

let memoryStore = new session.MemoryStore();

app.set('view engine', 'hbs');
app.set('trust proxy', 1); // trust first proxy

app.engine('hbs', handlebars({
    layoutsDir: __dirname + '/views/layouts',
    extname: 'hbs',
    defaultLayout: 'planB',
    partialsDir: __dirname + '/views/partials/'
}));

app.use(express.static('public'));
app.use(cors());

app.use(session({
    secret: 'keyboard cat',
    resave: false,
    store: memoryStore,
    saveUninitialized: true,
    cookie: { secure: true }
  }));

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// ***********************************************************
// These are the only parameters you need to provide
var domain = "acme.svipe.io";
const acmeKey = jose.JWK.asKey(fs.readFileSync('etc/privkey.pem'))
var requests = {"svipeid": {"essential":true}, "given_name":null, "family_name":null};
// ***********************************************************

var host = "https://"+domain;
//var host = "http://localhost:"+port; // For local dev

//const acmeKey = jose.JWK.asKey("7c3de020a79770277387799c2f04bfd20f8528ab733b506c13ba0625794687ad");

console.log(acmeKey.public);

app.get('/', (req, res) => {
    console.log(requests);
    var redirect_uri = host+"/callback"; 
    var logo = host + "/logo.png";
    var sessionID = req.sessionID;
    var aud = redirect_uri; 
    console.log(sessionID);
    generateQRCode(sessionID, redirect_uri, aud, requests, logo).then(function(srcpic) {
        res.render('main', {layout: 'index', logo: logo,  redirect_uri: redirect_uri, sessionID: sessionID, srcpic: srcpic, claims: requests});
    });
});

app.post('/callback', (req, res) => {
    console.log("callback");

    var uuid = req.body.uuid;
    var statusOK = JSON.stringify({status:'OK'});
    var statusNOK = JSON.stringify({status:'NOK'});
  
    var socket = clients[uuid];
    if (socket != undefined || socket != null ) {
      console.log("Has client for ", uuid);
      // now we need to verify stuff before updating ...
      var token = req.body.jwt;
      var parts = token.split('.');
      
      var header = JSON.parse(base64url.decode(parts[0]));
      var payload = JSON.parse(base64url.decode(parts[1]));
      var signature = base64url.decode(parts[2]);

      var sub_jwk = payload.sub_jwk;
      var sub = payload.sub;
      var isVerified = verifyPayload(header, payload, domain);

      console.log("sub_jwk", sub_jwk);
      console.log("sub", sub);
      console.log("verify payload",isVerified);

      if (isVerified) {
        var msg = {op:'authdone', jwt: token, sub: sub};
        console.log("callback msg",msg);
        socket.emit("message", msg);
        delete clients[uuid];
        // This is where you could set a cookie. 
        // The browser will redirect to the Welcome page specified by redirect_uri.
        res.end(statusOK);
      } else {
        console.error("could not verify token");
        res.end(statusNOK);
      }
    } else {
      res.end(statusNOK);
    }

})

// This must be relative to the client_id/redirect_uri

app.post('/callback/progress', (req, res) => {
    var uuid = req.body.uuid;
    var statusOK = JSON.stringify({status:'OK'});
    var statusNOK = JSON.stringify({status:'NOK'});
    var socket = clients[uuid];
    if (socket != undefined || socket != null ) {
      console.log("Has client to showProgress for ", uuid);
      var msg = {op:'progress', jwt: "scanned"};
      socket.emit("message", msg);
      res.end(statusOK);
    } else {
      console.error("Could not find client to showProgress for ", uuid);
      res.end(statusNOK);
    }
});

function verifyPayload(header, payload, aud) {

    // First the basics

    if (payload.sub_jwk === undefined) {
        console.error("sub_jwk missing");
        return false;
    }

    /* This is considered optional according to the standard and seems to cause problems with Android versions.
    if (payload.iat === undefined) {
        console.err("iat missing");
        return false;
    }
    */

    if (payload.exp === undefined) {
        console.error("exp missing");
        return false;
    }

    console.log("payload.aud", payload.aud);

    if (payload.aud === undefined) {
        console.error("aud missing");
        return false;
    } else if (Array.isArray(payload.aud)) {
      /* did not work for some reason, so to it clumsily
        if (!payload.aud.includes(aud)) {
            console.error("aud not in aud array");
            return false;
        }*/
        var found = false;
        for (i in payload.aud) {
          if (aud == payload.aud[i]) {
            found = true;
          }
        }
        if (!found) {
          return false;
        }
        
    } else if (payload.aud === aud) {
        console.error("payload.aud is not equal to aud");
        return false;
    }
    
    if ( header.kid !== payload.sub) {
        console.error("sub must be equal to kid");
        return false;
    }

    if (header.alg === undefined || header.alg === 'none' ) {
        console.error("no alg");
        return false;
    }
    console.log("payload verified");
    return true;
}

function generateQRCode(sessionID, redirect_uri, aud, claims, registration) {

    var nonce = sessionID;
    var state = sessionID;
    const jwk  = acmeKey.toJWK(true);
    console.log(jwk);
    
    var sub_jwk =  {
        y: jwk.y,
        use: "sig",
        kid: jwk.kid,
        x: jwk.x,
        kty: jwk.kty,
        crv: jwk.crv
    };

    var payload = {response_type: "id_token", client_id: redirect_uri, iss: domain,sub: jwk.kid, sub_jwk: sub_jwk, aud: [aud], 
    scope:"openid profile", state: state, nonce: nonce, registration: registration, claims: claims};
    console.log("payload", payload);
    var jwsCompact = jose.JWT.sign(payload, acmeKey, 
        {
            header: {
                kid: jwk.kid
            },
            expiresIn: "5m"
        }
    );
    console.log(jwsCompact);
    var urlString =  "https://app.svipe.io/auth/" + jwsCompact; // technically we could use openid:// to support other apps
    console.log("URL ",urlString);
    return QRCode.toDataURL(urlString);
}

io.on('connection', socket => {
    socket.on('message', msg => {
      console.log("received ",msg);
      if (msg.op == "hello" && msg.uuid) {
        var uuid = msg.uuid;
        clients[uuid] = socket;
        var msg = {op:'hello'};
        console.log("emit ",msg)
        io.emit('message', msg);
      } else {
          console.error("socket handshake failed");
      }
    });  
});

server.listen(port, () => console.log(`App listening to port ${port}`));