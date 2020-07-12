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

    console.log("memoryStore", memoryStore);

    var session = req.session;
    var sessionID = req.sessionID;
    var referrer = req.get('Referrer');
    var redirect_uri = req.query["redirect_uri"];
    var claims = req.query["claims"];
    session.redirect_uri = redirect_uri;
    console.log("session", session);
    console.log("sessionID", sessionID);
    console.log("session.store", session.store);
 
    if (verifyRP(redirect_uri)) {
        generateQRCode(sessionID,redirect_uri, claims).then(function(srcpic) {
            res.render('main', {layout: 'index', redirect_uri: redirect_uri, sessionID: sessionID, referrer: referrer, domain: "example.com", srcpic: srcpic});
        });
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
      console.log("verify payload",verifyPayload(header, payload));
      console.log("verify signature", jws.verify(signature,sub_jwk));

      if (true) /*(verifyPayload(header, payload) && jws.verify(signature,sub_jwk)) */ {
        var msg = {op:'authdone', jwt: token, sub: sub};
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
      console.log("Has client for ", uuid);
      var msg = {op:'progress', jwt: "scanned"};
      socket.emit("message", msg);
      res.end(statusOK);
    } else {
      res.end(statusNOK);
    }
});


function verifyRP(redirect_uri) {
    console.log("verifyRP",redirect_uri);
    return true;
}

function verifyPayload(header, payload) {

    // First the basics

    if (payload.sub_jwk === undefined) {
        console.err("sub_jwk missing");
        return false;
    }

    if (payload.iat === undefined) {
        console.err("iat missing");
        return false;
    }

    if (payload.exp === undefined) {
        console.err("exp missing");
        return false;
    }

    if (payload.aud === undefined) {
        console.err("aud missing");
        return false;
    } else if (Array.isArray(payload.aud)) {
        if (!payload.aud.includes(SvipeIDConfig.client_id)) {
            console.error("client_id not in aud array");
            return false;
        }
    } else if (payload.aud === SvipeIDConfig.client_id) {
        console.error("aud is not equal to client_id");
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

function generateQRCode(sessionID,redirect_uri, claims) {

    var queryString = composeQuery(sessionID,redirect_uri, claims);
    console.log("queryString",queryString);
    return QRCode.toDataURL(queryString);
}

function composeQuery(sessionID,redirect_uri, claims) {
  
    var nonce = sessionID;
    var state = sessionID;
    var registration = "";
    var SvipeIDConfig = {};

    var client_id = encodeURIComponent(SvipeIDConfig.client_id);
    if (SvipeIDConfig !=null && SvipeIDConfig.registration != null ) {
        $("#profile__logo__app-image").attr("src",SvipeIDConfig.registration);
        var registration = encodeURIComponent(SvipeIDConfig.registration);
    }
      
    // make token
  
    var jwt = {response_type: "id_token", client_id: redirect_uri, scope:"openid profile", state: state, nonce: nonce, registration: registration, claims: claims};
  
    console.log("jwt",jwt);
  
    var jwt_string = JSON.stringify(jwt);
    var jwt_token = Buffer.from(jwt_string).toString('base64');

    console.log("jwt_token",jwt_token);
  
    // var url = "openid://"+jwt_token;
    // var url = "openid://?response_type=id_token&client_id="+client_id+"&scope=openid%20profile&state="+state+"&nonce="+nonce+"&registration="+registration+"&claims="+claims;
    // To keep the QR code eligible we need to minimize the length. Maybe make most of the clientid default as well using well-known example.com
  
    //var socket_uri = "https://auth.svipe.io";

    queryString = "?client_id="+redirect_uri+"&nonce="+nonce+"&claims="+claims;
    console.log("claims", claims);
    console.log("queryString", queryString);
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