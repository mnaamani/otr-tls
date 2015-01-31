var enet = require("enet");
var otr = require("otr4-em");
var EventEmitter = require("events").EventEmitter;
var Stream = require("stream");

var DecryptStream = require('./cryptostream.js').DecryptStream;
var EncryptStream = require('./cryptostream.js').EncryptStream;

module.exports.createServer = function (options) {
	var server = {}; //otr transport server
	options = options || {};
	options.client = false;

	server.listen = function (callback) {
		enet.createServer({
			address: new enet.Address("0.0.0.0", options.port || 6666),
			peers: options.maxpeers || 32,
			channels: 2,
			down: 0,
			up: 0
		}, function (err, host) {
			if (err) {
				callback(err);
				return;
			}
			host.on("connect", function (peer, data) {
				//todo access control check on peer.address().address ip address...
				setupStreams(peer, options, function (fingerprint, otr_stream, aes_stream) {
					options.connect.call(server, {
							"otr": otr_stream,
							"aes": aes_stream,
						}, peer.address().address, peer.address().port,
						fingerprint);
				});
			});
			host.start(20);
			callback();
		});
	};

	return server;
};

module.exports.createClient = function (options) {
	var error;
	var host; //enet host
	var client = {}; //otr transport client
	var peer;
	options = options || {};
	options.client = true;

	//grab the host immediately
	host = enet.createClient({
		peers: 1,
		channels: 2,
		down: 0,
		up: 0
	}, function (_err) {
		error = _err;
		return;
	});

	client.connect = function (ip, port, server_fingerprint) {
		if (error || !host) {
			throw (error || "client-destroyed"); //host is destroyed or was not created - throw it when client tries to connect
		}

		if (peer) return; //once connecition at a time

		options.server_fingerprint = server_fingerprint;

		peer = host.connect(new enet.Address(ip, port));

		peer.on("connect", function () {
			setupStreams(peer, options, function (fingerprint, otr_stream, aes_stream) {
				options.connect.call(client, {
					"otr": otr_stream,
					"aes": aes_stream
				}, peer.address().address, peer.address().port, fingerprint);
			});
		});

		peer.on("disconnect", function () {
			peer = undefined;
		});
	};

	client.disconnect = function () {
		peer.disconnect();
		host.flush();
	};

	client.connected = function () {
		return (peer ? peer.state() === enet.PEER_STATE.CONNECTED : false);
	};

	client.end = function () {
		host.destroy();
	};

	return client;
};


function setupStreams(peer, options, callback) {
	var aesKeys = {};
	var chan0 = peer.createDuplexStream(0);

	var remote = options.account.contact(peer.address().address + peer.address().port);

	var session = remote.openSession({
		policy: otr.POLICY.ALWAYS
	});

	//internally handle OTR fragments from network and inject fragments to network
	var fragments = otrFragmentsStream(session);

	chan0.pipe(fragments).pipe(chan0);

	peer.on("disconnect", function () {
		chan0.unpipe(fragments);
		fragments.unpipe(chan0);
	});

	//should not be caught because we are unpiping on disconnect...
	chan0.on("error", function (e) {
		console.error("error on channel0:", e);
	});

	session.on("gone_secure", function () {
		//todo - clear timeout waiting for secure session.

		//todo client access-control on fingerprint

		//client verifies fingerprint of server..
		if (options.client && options.server_fingerprint) {
			if (options.server_fingerprint !== session.theirFingerprint()) {
				session.end();
				peer.disconnectLater();
				return;
			}
		}
		//setup extra symmetric keys for AES stream - each side will tell the other they wish to use the extra symmetric key
		//which will result in two, keys being computed, one for sending and one for receiving.
		aesKeys.sending = session.extraSymKey(1, 'transport');
	});

	session.on("received_symkey", function (use, usedata, key) {
		aesKeys.receiving = key;
		callback(session.theirFingerprint(), otrMessagesStream(session, peer), aesStream(peer, aesKeys));
	});

	if (options.client) {
		session.start(); //client starts otr protocol
	}
	//todo - add a timeout wait for secure connection - maybe otherside doesn't respond to OTR query..

}

function aesStream(peer, keys) {
	var chan1 = peer.createDuplexStream(1);
	var stream = new Stream.Duplex();

	//review http://tools.ietf.org/html/rfc3686 to do proper AES stream encryption
	var encrypt = new EncryptStream(keys.sending.toString());
	var decrypt = new DecryptStream(keys.receiving.toString());

	chan1.on("error", function (e) {
		console.error("error on channel1:", e);
	});

	peer.on("disconnect", function () {
		//classic streams don't have an unpipe() method:
		encrypt.removeAllListeners("data");
		decrypt.removeAllListeners("data");
		chan1.unpipe(decrypt);
		stream.push(null);
	});

	encrypt.pipe(chan1).pipe(decrypt);

	stream._write = function (buf, enc, next) {
		if (peer.state() === enet.PEER_STATE.CONNECTED) {
			encrypt.write(buf);
			next();
			return;
		}
		next("peer-disconnected");
	};

	stream._read = function () {};

	decrypt.on("data", function (buf) {
		stream.push(buf);
	});

	stream.on("finish", function () {
		encrypt.removeAllListeners("data"); //stops sending to channel
	});

	return stream;

}

function otrMessagesStream(session, peer) {
	var s = new Stream.Duplex();

	s._write = function (buf, enc, next) {
		if (peer.state() !== enet.PEER_STATE.CONNECTED) {
			next("peer-disconnected");
			return;
		}
		if (!session.isEncrypted()) {
			next("otr-session-ended");
		}
		session.send(buf);
		next();
	};

	s._read = function () {};

	session.on("disconnect", function () {
		s.push(null);
	});

	peer.on("disconnect", function () {
		session.end();
		s.push(null);
	});

	session.on("message", function (msg, encrypted) {
		if (encrypted) {
			s.push(msg);
		}
	});

	s.on("finish", function () {
		session.end();
		s.push(null);
	});

	return s;
}

function otrFragmentsStream(session) {
	var s = new Stream.Duplex();

	s._write = function (buf, enc, next) {
		session.recv(buf);
		next();
	};

	s._read = function () {};

	session.on("inject_message", function (msg) {
		s.push(msg);
	});

	return s;
}

/** Return an otr.Account
 * loads key from file system or generates a new key if not found
 */
module.exports.account = function (options, callback) {
	var name = options.name || "default";
	var keys = './keys-' + name;
	keys = options.keys || keys;

	var user = new otr.User({
		keys: keys
	});

	var account = user.account(name, "otr.transport");

	if (account.fingerprint()) {
		account.generateInstag();
		callback(account);
		return;
	}

	console.log("generating new key...");
	account.generateKey(function (err) {
		if (err) {
			account = undefined;
			console.error("error generating key:", err);
		} else {
			user.saveKeysToFS(keys);
			account.generateInstag();
		}
		callback(account);
	});
};
