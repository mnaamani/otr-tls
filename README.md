otr-transport-enet
=======

Off-the-record messaging protocol (OTR) is protocol agnostic but is typically used ontop of an instant messaging protocol (xmpp) to offer secure chat.
otr-transport is an example of using OTR as client-server networking protocol similar to ssh using the OTRv3.

##Ideas

* ENet for reliable transport over UDP.

* Multiplexed channels/streams encrypted with AES.

* Identities of clients and servers are simply the public key fingerprint.

* Server access control/authorisation by publick key fingerprint.

* Client verifies server identity by publick key fingerprint.

* Incorporate OTRDATA TLVs
https://lists.cypherpunks.ca/pipermail/otr-dev/2014-December/002266.html

Work In Progress...
