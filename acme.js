const express = require('express');
const app = express();

const handlebars = require('express-handlebars');
const session = require('express-session');
var jwt = require('express-jwt');
const QRCode = require('qrcode');
const { Store } = require('express-session');
const bodyParser = require('body-parser');
const server = require('http').Server(app);
const io = require('socket.io')(server);
const cors = require('cors');
var clients = {}; // Keep track of outstanding connections
const base64url = require('base64url');
const jws = require('jws-jwk');
var url = require('url');
require('https').globalAgent.options.ca = require('ssl-root-cas/latest').create();

var isCompact = false;
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

// Change when going live
//var host = "https://acme.svipe.io";
var host = "http://localhost:"+port;

app.get('/', (req, res) => {
    var claims = {"svipeid": {"essential":true}, "given_name":null, "family_name":null};
    console.log(claims);
    var redirect_uri = host + "/callback"; 
    var logo = host + "/logo.png";
    var sessionID = req.sessionID;
    console.log(sessionID);
    generateQRCode(sessionID, redirect_uri, claims, logo).then(function(srcpic) {
        res.render('main', {layout: 'index', logo: logo,  redirect_uri: redirect_uri, sessionID: sessionID, srcpic: srcpic, claims: claims});
    });
});

app.post('/callback', (req, res) => {

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

      var isVerified = verifyPayload(header, payload);

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

function verifyPayload(header, payload) {

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

    if (payload.aud === undefined) {
        console.error("aud missing");
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

function generateQRCode(sessionID,redirect_uri,claims,registration) {
    
    var nonce = sessionID;
    var state = sessionID;
  
    // make token
  
    var jwt = {response_type: "id_token", client_id: redirect_uri, scope:"openid profile", state: state, nonce: nonce, registration: registration, claims: claims};
  
    console.log("jwt",jwt);
  
    var jwt_string = JSON.stringify(jwt);
    var jwt_token = Buffer.from(jwt_string).toString('base64');

    console.log("jwt_token",jwt_token);
  
    if (isCompact) {
        queryString = jwt_token
    } else {
        if (claims)  {
            queryString = "?client_id="+encodeURIComponent(redirect_uri)+"&nonce="+nonce+"&claims="+encodeURIComponent(claims);
        } else {
            queryString = "?client_id="+encodeURIComponent(redirect_uri)+"&nonce="+nonce;
        }
    }
    console.log("claims", claims);
    var urlString =  "openid://" + queryString;
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