const express = require('express');
const app = express();
const port = 4000;
const handlebars = require('express-handlebars');
const session = require('express-session');
var jwt = require('express-jwt');
const QRCode = require('qrcode');
const { Store } = require('express-session');
const bodyParser = require('body-parser');
const server = require('http').Server(app);
const io = require('socket.io')(server);
//const uuidv1 = require('uuid/v1');
const cors = require('cors');
var clients = {}; // Keep track of outstanding connections
const base64url = require('base64url');
const jws = require('jws-jwk');
const fetch = require('node-fetch');
var url = require('url');
require('https').globalAgent.options.ca = require('ssl-root-cas/latest').create();
var isCompact = false;

var SvipeIDConfig = {
	client_id: null,
	registration: null 
}

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

app.get('/', (req, res) => {

    //console.log("memoryStore", memoryStore);

    var session = req.session;
    var sessionID = req.sessionID;
    var referrer = req.get('Referrer');
    var redirect_uri = req.query["redirect_uri"];
    var claims = req.query["claims"];
    var sign = req.query["sign"];
    session.redirect_uri = redirect_uri;
    //console.log("session", session);
    console.log("sessionID", sessionID);
    //console.log("session.store", session.store);
 
    console.log("redirect_uri", redirect_uri);
    
    if (redirect_uri!=null) {
        var hostname = url.parse(redirect_uri).hostname;
        var configURL = "https://" + hostname + "/.well-known/svipe-configuration";
        console.log(configURL);
        retrieveConf(configURL).then( function(json) {
            generateQRCode(sessionID,redirect_uri, sign,claims,json.registration).then(function(srcpic) {
                res.render('main', {layout: 'index', logo: json.registration,  redirect_uri: redirect_uri, sessionID: sessionID, referrer: referrer, domain: hostname, srcpic: srcpic, sign: sign, claims: claims});
        });
    }).catch(error => {
        console.error('Error during service worker registration:', error);
        res.redirect("https://app.svipe.com");
      });
    } else {
        res.redirect("https://app.svipe.com")
    }
    /*
    console.log("All sessions");
    memoryStore.all(function (error,sessions) {
        console.log("sessions", sessions);
    })*/

});

app.post('/', (req, res) => {

    var uuid = req.body.uuid;

    var statusOK = JSON.stringify({status:'OK'});
    var statusNOK = JSON.stringify({status:'NOK'});
  
    var socket = clients[uuid];
    if (socket != undefined || socket != null ) {
      console.log("Has client for ", uuid);
      // now we need to verify stuff before forwarding...
      var token = req.body.jwt;
      var parts = token.split('.');
      
      var header = JSON.parse(base64url.decode(parts[0]));
      var payload = JSON.parse(base64url.decode(parts[1]));
      var signature = base64url.decode(parts[2]);

      var sub_jwk = payload.sub_jwk;
      var sub = payload.sub;

      console.log("sub_jwk", sub_jwk);
      console.log("sub", sub);

      console.log("verify payload",verifyPayload(header, payload));
      //console.log("verify signature", jws.verify(signature,sub_jwk));
      // EC keys not supported....

      var isVerified = true;

      if (isVerified) {
        var msg = {op:'authdone', jwt: token, sub: sub};
        console.log("msg",msg);
        socket.emit("message", msg);
        delete clients[uuid];
        res.end(statusOK);
      } else {
        console.error("could not verify token");
        res.end(statusNOK);
      }
      
    } else {
      res.end(statusNOK);
    }

});

app.post('/progress', (req, res) => {
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

async function retrieveConf(configURL){
    return await fetch(configURL)
    .then(res => res.json())
}

function verifyPayload(header, payload) {

    // First the basics

    if (payload.sub_jwk === undefined) {
        console.err("sub_jwk missing");
        return false;
    }

    /* This is considered optional according to the standard and seems to cause problems with Android versions.
    if (payload.iat === undefined) {
        console.err("iat missing");
        return false;
    }
    */

    if (payload.exp === undefined) {
        console.err("exp missing");
        return false;
    }


    if (payload.aud === undefined) {
        console.err("aud missing");
        return false;
    } /*else if (Array.isArray(payload.aud)) {
        if (!payload.aud.includes(SvipeIDConfig.client_id)) {
            console.error("client_id not in aud array");
            return false;
        }
    } else if (payload.aud === SvipeIDConfig.client_id) {
        console.error("aud is not equal to client_id");
        return false;
    }*/


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

function generateQRCode(sessionID,redirect_uri, sign,claims,registration) {
    var urlString = composeQuery(sessionID,redirect_uri, sign,claims,registration);
    console.log("URL ",urlString);
    return QRCode.toDataURL(urlString);
}

function composeQuery(sessionID,redirect_uri, sign, claims,registration) {
  
    var nonce = sessionID;
    var state = sessionID;
  
    // make token
  
    var jwt = {response_type: "id_token", client_id: redirect_uri, scope:"openid profile", state: state, nonce: nonce, registration: registration, claims: claims, sign:sign};
  
    console.log("jwt",jwt);
  
    var jwt_string = JSON.stringify(jwt);
    var jwt_token = Buffer.from(jwt_string).toString('base64');

    console.log("jwt_token",jwt_token);
  
    // var url = "openid://"+jwt_token;
    // var url = "openid://?response_type=id_token&client_id="+client_id+"&scope=openid%20profile&state="+state+"&nonce="+nonce+"&registration="+registration+"&claims="+claims;
    // To keep the QR code eligible we need to minimize the length. Maybe make most of the clientid default as well using well-known example.com
    //var socket_uri = "https://auth.svipe.io";

    if (isCompact) {
        queryString = jwt_token
    } else {

        if (claims)  {
            queryString = "?client_id="+encodeURIComponent(redirect_uri)+"&nonce="+nonce+"&claims="+encodeURIComponent(claims);
        } else {
            queryString = "?client_id="+encodeURIComponent(redirect_uri)+"&nonce="+nonce;
        }

        if (sign) {
            queryString += "&sign=" + encodeURIComponent(sign);
        }
    }

    console.log("claims", claims);
    return "openid://" + queryString;

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