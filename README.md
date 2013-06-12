otr-tls
=======

##OTR Transport Layer Security Protocol?

Off-the-record messaging protocol (OTR) was designed to run ontop of an instant messaging protocol (xmpp) to offer secure chatting.
otr-tls is an attempt at building a secure client-server networking protocol similar to TLS using the OTRv3 protocol.

##Ideas

* ENet for reliable transport over UDP and NAT traversal.

* Multiplexed channels/streams encrypted with AES.

* Identities of clients and servers are simply the public key fingerprint.
* Server access control/authorisation by publick key fingerprint.
* Client verifies server identity by publick key fingerprint.

* Decentralised public directory for publishing fingerprints - combination of DNSSEC, public profiles (facebook,twitter,website metadata..), web of trust..?
  
Work In Progress...
--------------------------

experiments to try..
*modify node http/s module to use otr-tls instead of tcp"

