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
var request = require('request');
const fetch = require('node-fetch');
const server = require('http').Server(app);
const io = require('socket.io')(server);
const cors = require('cors');
const base64url = require('base64url');
const jose = require('jose');
const crypto = require('crypto');
const { Session } = require('inspector');
var clients = {}; // Keep track of outstanding connections
var tokens = {}; // Outstanding membership tokens that the client might pickup

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
const acmeKey = jose.JWK.asKey(fs.readFileSync('etc/privkey.pem'));

var credential =  {iss: "Acme", name: "Covid19", type: "Vaccination", id: null}
var requests2 = { credential: credential}; // id could f.i be a certain batch

var requests = {svipeid: {essential:true}, given_name:null, family_name: null};

// iss: null means any issuer, the same for the other attributes
// 
// ***********************************************************

var host = "https://"+domain;
//var host = "http://localhost:"+port; // For local dev

app.get('/svipe', (req, res) => {
  res.render('svipe', {layout: 'index'});
});

app.get('/srcpic', (req, res) => {
  console.log("SRCPIC", req);
  var redirect_uri = host+"/callback"; 
  var logo = host + "/logo.png";
  var sessionID = req.sessionID;
  var aud = redirect_uri; 
  console.log("sessionID", sessionID);
  var requests = {svipeid: {essential:true}, given_name:null, family_name: null, document_number: null};
  generateSigninCode("auth",sessionID, redirect_uri, aud, requests, logo).then( function(response) {
    var srcpic = response.srcpic;
    var jwsCompact = response.jwsCompact;
    console.log("srcpic requests", requests);
    res.render('srcpic', {layout: 'index', logo: logo,  redirect_uri: redirect_uri, sessionID: sessionID, srcpic: srcpic, claims: requests, jwsCompact:jwsCompact});
  });
});

app.get('/', (req, res) => {
    console.log("HOME");
    var redirect_uri = host+"/callback"; 
    var logo = host + "/logo.png";
    var sessionID = req.sessionID;
    var aud = redirect_uri; 
    console.log(sessionID);
    generateSigninCode("auth",sessionID, redirect_uri, aud, requests, logo).then( function(response) {
      var srcpic = response.srcpic;
      console.log(srcpic);
      var jwsCompact = response.jwsCompact;
      console.log("requests", requests);
      res.render('main', {layout: 'index', logo: logo,  redirect_uri: redirect_uri, sessionID: sessionID, srcpic: srcpic, claims: requests, jwsCompact:jwsCompact});
    });
});


app.get('/form', (req, res) => {
  res.render('form', {layout: 'index'});
});

// Demo how to sign a contract

app.get('/sign', (req, res) => {
  var redirect_uri = host+"/callback"; 
  var logo = host + "/logo.png";
  var sessionID = req.sessionID;
  var aud = redirect_uri; 
  console.log(sessionID);

  var signature_request = "https://www.lipsum.com/privacy.pdf"
  var requests = {svipeid: {essential:true}, given_name:null, family_name: null, signature_request: signature_request};

  generateSigninCode("auth",sessionID, redirect_uri, aud, requests, logo).then( function(response) {
    var srcpic = response.srcpic;
    var jwsCompact = response.jwsCompact;
    console.log("requests", requests);
    res.render('sign', {layout: 'index', logo: logo,  redirect_uri: redirect_uri, sessionID: sessionID, srcpic: srcpic, claims: requests, jwsCompact:jwsCompact, signature_request:signature_request});
  });
});

app.get('/welcome/:jws', (req, res) => {
  // hmm, need to verify again. in case the token was modfied in the browser
  var token = req.params["jws"];
  if (token != null) {
    console.log("token", token);
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
    var logo = host + "/logo.png";
    // could really do this in handlebars instead
    var name = "";
    var svipeid = payload.claims["svipeid"];
    var given_name = payload.claims["given_name"];
    var family_name = payload.claims["family_name"];
    if (given_name) {
      name += given_name;
    }
    if (family_name) {
      name += " " + family_name;
    }

    var credential = payload.claims["credential"];
    var redirect_uri = host+"/callback"; 
    var logo = host + "/logo.png";

    if (credential != null) {
      var badge = JSON.stringify(credential);
      res.render('members', {layout: 'index', logo: logo, badge: badge});
    } else {
      var sessionID = req.sessionID;
      var aud = redirect_uri; 
      var serial_number = 1;
      var claims = { credential: {iss: "Acme", name: "Covid19", type: "Vaccination", id: serial_number, svipeid: svipeid}}; // This is what is issued. The client will only add if svipeid matches
      //var hash = crypto.createHash('sha256').update('alice', 'utf8').digest();
      var fileURL = "https://www.lipsum.com/privacy.pdf"; 
      var signature_request = {data: fileURL, hash:"aedac29095f2765f052578585fcac91ef542cfe797469e788e527854315845ad"};
      console.log("signature_request",signature_request);
      var requests3 = {signature_request: signature_request, svipeid: {essential:true}};
      
      generateWelcomeCodes("cred",sessionID, redirect_uri, aud, claims, requests2,requests3, logo).then( function(response) {
        var srcpic = response.srcpic;
        var jwsCompact = response.jwsCompact;
        var srcpic2 = response.srcpic2;
        var jwsCompact2 = response.jwsCompact2;
        var srcpic3 = response.srcpic3;
        var jwsCompact3 = response.jwsCompact3;
        console.log("requests", requests);
        res.render('welcome', {layout: 'index', credential: credential,sessionID: sessionID, logo: logo, name: name, 
          srcpic: srcpic, jwsCompact: jwsCompact, 
          srcpic2: srcpic2, jwsCompact2: jwsCompact2,
          srcpic3: srcpic3, jwsCompact3: jwsCompact3
        });
      });
    }
  }
})

app.get('/members/:jws', (req, res) => {
  // hmm, need to verify again. in case the token was modfied in the browser
  var token = req.params["jws"];
  if (token != null) {
    console.log("token", token);
    var parts = token.split('.');
    var header = JSON.parse(base64url.decode(parts[0]));
    var payload = JSON.parse(base64url.decode(parts[1]));
    var isVerified = verifyPayload(header, payload, domain);
    var logo = host + "/logo.png";
    var badge = JSON.stringify(payload.claims["credential"], null, 2);
    var signature = JSON.stringify(payload.claims["signature_request"], null, 2);
    console.log("badge",badge);
    res.render('members', {layout: 'index', logo: logo, badge: badge, signature: signature});
  }
})

// This happens when using a mobile browser, so we bypass the socket in this case
app.get('/callback/:jws', (req, res) => {
  var jws = req.params["jws"];
  console.log("callback", jws);
  res.redirect("/welcome/"+jws);
})

app.get('/callback2/:jws', (req, res) => {
  var jws = req.params["jws"];
  console.log("callback", jws);
  res.redirect("/members/"+jws);
})

app.get('/callback/token/:uuid', (req, res) => {
  var uuid = req.params["uuid"];
  console.log("uuid", uuid);
  var token = tokens[uuid];
  if (token != undefined || token != null ) {
    console.log("found badge token");
    res.send(token);
    //delete tokens[uuid]; // can only be picked up once
  } else {
    console.error("could not find token for ",uuid," in ", tokens);
    res.send("already used");
  }
})


app.post('/callback_form', (req, res) => {

  console.log("posted to callback");
 
  var uuid = req.body.uuid;
  var statusOK = JSON.stringify({status:'OK'});
  var statusNOK = JSON.stringify({status:'NOK'});

  var socket = clients[uuid];
  if (socket != undefined || socket != null ) {
    console.log("Has client for ", uuid);
    // now we need to verify stuff before updating ...
    var token = req.body.jwt;
    var parts = token.split('.');
    console.log("received jwt", token);
    var header = JSON.parse(base64url.decode(parts[0]));
    var payload = JSON.parse(base64url.decode(parts[1]));
    var signature = base64url.decode(parts[2]);

    var sub_jwk = payload.sub_jwk;
    var sub = payload.sub;
    var isVerified = verifyPayload(header, payload, domain);

    console.log("sub_jwk", sub_jwk);
    console.log("sub", sub);
    console.log("verify payload", isVerified);

    if (isVerified) {
      var msg = {op:'authdone', jwt: token, sub: sub};
      console.log("callback msg",msg);
      socket.emit("message", msg);
      var svipeid = payload.claims.svipeid;
      var claims = { credential: {iss: "Acme", name: "Covid19", type: "Vaccination", id: svipeid}}; // This is what is issued. The client will only add if svipeid matches
      var logo = host + "/logo.png";
      var redirect_uri = host+"/callback_form"; 
      var aud = redirect_uri; 
      memberBadge("cred",uuid, redirect_uri, aud, claims, logo).then( function(response) {
        var jwsCompact = response.jwsCompact;
        tokens[uuid] = jwsCompact;
      });
      // This is where you could set a cookie. 
      // The browser will redirect to the Welcome page specified by redirect_uri.
      res.end(statusOK);
    } else {
      console.error("could not verify token");
      res.end(statusNOK);
    }
  } else {
    console.error("uuid ",uuid);
    res.end(statusNOK);
  }
})

app.post('/callback', (req, res) => {

    console.log("posted to callback");
   
    var uuid = req.body.uuid;
    var statusOK = JSON.stringify({status:'OK'});
    var statusNOK = JSON.stringify({status:'NOK'});
  
    var socket = clients[uuid];
    if (socket != undefined || socket != null ) {
      console.log("Has client for ", uuid);
      // now we need to verify stuff before updating ...
      var token = req.body.jwt;
      var parts = token.split('.');
      console.log("received jwt", token);
      var header = JSON.parse(base64url.decode(parts[0]));
      var payload = JSON.parse(base64url.decode(parts[1]));
      var signature = base64url.decode(parts[2]);

      var sub_jwk = payload.sub_jwk;
      var sub = payload.sub;
      var isVerified = verifyPayload(header, payload, domain);

      console.log("sub_jwk", sub_jwk);
      console.log("sub", sub);
      console.log("verify payload", isVerified);

      if (isVerified) {
        var msg = {op:'authdone', jwt: token, sub: sub};
        console.log("callback msg",msg);
        socket.emit("message", msg);
        var svipeid = payload.claims.svipeid;
        var claims = { credential: {iss: "Acme", name: "Covid19", type: "Vaccination", id: svipeid}}; // This is what is issued. The client will only add if svipeid matches
        var logo = host + "/logo.png";
        var redirect_uri = host+"/callback"; 
        var aud = redirect_uri; 
        memberBadge("cred",uuid, redirect_uri, aud, claims, logo).then( function(response) {
          var jwsCompact = response.jwsCompact;
          tokens[uuid] = jwsCompact;
        });
        // This is where you could set a cookie. 
        // The browser will redirect to the Welcome page specified by redirect_uri.
        res.end(statusOK);
      } else {
        console.error("could not verify token");
        res.end(statusNOK);
      }
    } else {
      console.error("uuid ",uuid);
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
      console.log("clients", clients);
      console.error("Could not find client to showProgress for ", uuid);
      res.end(statusNOK);
    }
});

async function fileHash(url, algorithm = 'sha256') {
  return new Promise((resolve, reject) => {
    let shasum = crypto.createHash(algorithm);
    try {
      let s = fetch(url);
      console.log("pdf", s);
      shasum.update(s);
      const hash = shasum.digest('hex');
      return resolve(hash);
    } catch (error) {
      return reject('calc fail');
    }
  });
}

function verifyPayload(header, payload, aud) {

    return true; // some verification fails

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


function shorten(data) {
  return new Promise((resolve, reject) => {
      request.post({
        headers: {'content-type' : 'application/x-www-form-urlencoded'},
        url:     "https://api.dev.bes.svipeid.com/v1/shortenurl",
        //url:     "https://api.svipe.com/v1/shortenurl",
        body:    data
      }, (error, response, body) => {
          if (error) reject(error);
          if (response.statusCode != 200) {
              reject('Invalid status code <' + response.statusCode + '>');
          }
          resolve(body);
      });
  });
}


async function memberBadge(path,sessionID, redirect_uri, aud, claims, registration) {

  var sub_jwk  = acmeKey.toJWK(true);
  sub_jwk.use = "sig"

  var payload = {response_type: "id_token", client_id: redirect_uri, iss: domain,sub: sub_jwk.kid, sub_jwk: sub_jwk, aud: [aud], 
  scope:"openid profile", state: sessionID, nonce: sessionID, registration: registration, claims: claims};
  console.log("payload", payload);

  var jwsCompact = jose.JWT.sign(payload, acmeKey, 
      {
          header: {
              kid: sub_jwk.kid
          },
          expiresIn: "5m"
      }
  )
  console.log(jwsCompact);
  
  try {
    var token = await shorten(jwsCompact);
    var urlString = "https://app.svipe.io/"+path+"/"+token;
    console.log("token", token);
    console.log("URL ", urlString);
    var ret =  {srcpic: await QRCode.toDataURL(urlString), jwsCompact: jwsCompact};
    return ret;
  } catch { // Display a friendly error page
    console.error("qr");
  }
  
}

async function generateWelcomeCodes(path,sessionID, redirect_uri, aud, claims, claims2, claims3, registration) {

    var sub_jwk  = acmeKey.toJWK(true);
    sub_jwk.use = "sig"

    var payload = {response_type: "id_token", client_id: redirect_uri, iss: domain,sub: sub_jwk.kid, sub_jwk: sub_jwk, aud: [aud], 
    scope:"openid profile", state: sessionID, nonce: sessionID, registration: registration, claims: claims};
    console.log("payload", payload);

    var payload2 = {response_type: "id_token", client_id: redirect_uri, iss: domain,sub: sub_jwk.kid, sub_jwk: sub_jwk, aud: [aud], 
    scope:"openid profile", state: sessionID, nonce: sessionID, registration: registration, claims: claims2};
    console.log("payload2", payload2);

    var payload3 = {response_type: "id_token", client_id: redirect_uri, iss: domain,sub: sub_jwk.kid, sub_jwk: sub_jwk, aud: [aud], 
    scope:"openid profile", state: sessionID, nonce: sessionID, registration: registration, claims: claims3};
    console.log("payload3", payload3);

    var jwsCompact = jose.JWT.sign(payload, acmeKey, 
        {
            header: {
                kid: sub_jwk.kid
            },
            expiresIn: "5m"
        }
    )
    console.log("sessionID",sessionID);
    tokens[sessionID] = jwsCompact;

    var jwsCompact2 = jose.JWT.sign(payload2, acmeKey, 
      {
          header: {
              kid: sub_jwk.kid
           },
          expiresIn: "5m"
      }
    )


    var jwsCompact3 = jose.JWT.sign(payload3, acmeKey, 
      {
          header: {
              kid: sub_jwk.kid
           },
          expiresIn: "5m"
      }
    )
    console.log(jwsCompact);
    console.log(jwsCompact2);
    console.log(jwsCompact3);

    try {
      var token = await shorten(jwsCompact);

      var urlString = "https://app.svipe.io/"+path+"/"+token;
      console.log("token", token);
      console.log("URL ", urlString);

      var token2 = await shorten(jwsCompact2);
      var urlString2 = "https://app.svipe.io/auth/"+token2;
      console.log("token2", token2);
      console.log("URL ", urlString2);

      var token3 = await shorten(jwsCompact3);
      var urlString3 = "https://app.svipe.io/auth/"+token3;
      console.log("token3", token3);
      console.log("URL ", urlString3);

      var ret =  {srcpic: await QRCode.toDataURL(urlString), jwsCompact: jwsCompact, srcpic2: await QRCode.toDataURL(urlString2), jwsCompact2: jwsCompact2, srcpic3: await QRCode.toDataURL(urlString3), jwsCompact3: jwsCompact3};
      return ret;
    } catch { // Display a friendly error page
      console.error("qr");
    }
    
}


async function generateSigninCode(path,sessionID, redirect_uri, aud, claims, registration) {

  var sub_jwk  = acmeKey.toJWK(true);
  sub_jwk.use = "sig"

  var payload = {response_type: "id_token", client_id: redirect_uri, iss: domain,sub: sub_jwk.kid, sub_jwk: sub_jwk, aud: [aud], 
  scope:"openid profile", state: sessionID, nonce: sessionID, registration: registration, claims: claims};
  console.log("payload", payload);

  var jwsCompact = jose.JWT.sign(payload, acmeKey, 
      {
          header: {
              kid: sub_jwk.kid
          },
          expiresIn: "5m"
      }
  )

  console.log(jwsCompact);

  try {
    var token = await shorten(jwsCompact);
    var urlString = "https://app.svipe.io/"+path+"/"+token;
    console.log("token", token);
    console.log("URL ", urlString);
    var ret =  {srcpic: await QRCode.toDataURL(urlString), jwsCompact: jwsCompact};
    return ret;
  } catch { // Display a friendly error page
    console.error("qr");
  }
  
}

io.on('connection', socket => {
  console.log("set up socket");
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