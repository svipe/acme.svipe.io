# ACME

An example of a node.js integration with Svipe iD.

- We request svipeid, given_name and family_name
- We sign a JWS using a dummy key (that must be registered with Svipe)
- A QR code is displayed
- User signs with the Svipe App
- Wait for a token to be posted and communicated to the browser over a websocket

