const express = require('express');
const app = express();
const port = 4000;
const handlebars = require('express-handlebars');
const session = require('express-session');
var jwt = require('express-jwt');
const QRCode = require('qrcode');

app.set('view engine', 'hbs');
app.set('trust proxy', 1); // trust first proxy

app.engine('hbs', handlebars({
    layoutsDir: __dirname + '/views/layouts',
    extname: 'hbs',
    defaultLayout: 'planB',
    partialsDir: __dirname + '/views/partials/'
}));

app.use(express.static('public'));

app.use(session({
    secret: 'keyboard cat',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: true }
  }));

app.get('/', (req, res) => {
    var session = req.session;
    console.log("session", session);
    var sessionID = req.sessionID;
    console.log("sessionID", req.sessionID);
 
    var referrer = req.get('Referrer');
    console.log("Referrer", referrer);
    var redirect_uri = req.query["redirect_uri"];
    console.log("redirect_uri",redirect_uri);
    var claims = req.query["claims"];
    console.log("claims", claims);

    if (verifyRP(redirect_uri)) {
        generateQRCode(sessionID,redirect_uri, claims).then(function(srcpic) {
            res.render('main', {layout: 'index', referrer: referrer, domain: "example.com", srcpic: srcpic});
        });
    }
    //res.redirect(ref);
});

function verifyRP(redirect_uri) {
    console.log("verifyRP",redirect_uri);
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
  
    queryString = "?client_id="+redirect_uri+"&nonce="+nonce+"&claims="+claims;
    console.log("claims", claims);
    console.log("queryString", queryString);
  
    return "openid:" + queryString;

 }
  

app.listen(port, () => console.log(`App listening to port ${port}`));