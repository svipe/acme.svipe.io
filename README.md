# ACME

An example of a node.js integration with Svipe iD.

We request svipeid and full name
New users are registered in sqlite DB
Returning users are updated with last access and number of visits

We sign a JWS using a dummy key (that must be registered with Svipe)

A QR code is displayed

Wait for a token over websocket

