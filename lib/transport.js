var enet = require("enet");
var otr = require("otr4-em");
var EventEmitter = require("events").EventEmitter;
var Stream = require("stream");
var uuid = require("node-uuid");

var DecryptStream = require('./cryptostream.js').DecryptStream;
var EncryptStream = require('./cryptostream.js').EncryptStream;

module.exports.createServer = function (options) {
	var server = {}; //otr transport server
	var host, listening = false;
	options.client = false;
	//todo check options.account has key and instag

	server.listen = function (callback) {
		if (host || listening) {
			throw (new Error("already listening"));
		}
		listening = true;
		enet.createServer({
			address: new enet.Address(options.address || "0.0.0.0", options.port || 6666),
			peers: options.maxpeers || 32,
			channels: 2,
			down: 0,
			up: 0
		}, function (err, _host) {
			if (err) {
				callback(err);
				return;
			}
			host = _host;

			host.on("connect", function (peer, data) {
				setupStreams(peer, options, undefined, function (err, fingerprint, otr_stream,
					aes_stream) {
					if (err) {
						return;
					}
					var connection = {
						"otr": otr_stream,
						"aes": aes_stream,
						"address": peer.address().address,
						"port": peer.address().port,
						"fingerprint": fingerprint
					};

					options.onConnect(connection);

					peer.on("disconnect", function () {
						if (typeof connection.onDisconnect === 'function')
							connection.onDisconnect.call();
					});

					connection.disconnect = function () {
						if (peer) peer.disconnectLater();
					};

					connection.connected = function () {
						return (peer ? peer.state() === enet.PEER_STATE.CONNECTED :
							false);
					};

				});
			});

			host.start();

			callback();
		});
	};

	server.close = function () {
		setTimeout(function () {
			host.stop();
		}, 100);
	};

	return server;
};

module.exports.createClient = function (options) {
	var error;
	var host; //enet host
	var client = {}; //otr transport client

	//todo check options.account has key and instag

	options.client = true;

	//grab the host immediately
	host = enet.createClient({
		peers: 32,
		channels: 2,
		down: 0,
		up: 0
	}, function (err) {
		error = err;
		return;
	});

	client.connect = function (address, callback, fingerprint) {
		if (error || !host) {
			//host is destroyed or was not created - throw it when client tries to connect
			callback(error || "client-destroyed");
			return;
		}

		var peer;
		var connecting = false;
		var connection = {};

		peer = host.connect(address);
		connecting = true;

		peer.on("connect", function () {
			connecting = false;
			setupStreams(peer, options, fingerprint, function (err, fingerprint, otr_stream, aes_stream) {
				if (err) {
					peer = undefined;
					callback(err);
					return;
				}
				connection.otr = otr_stream;
				connection.aes = aes_stream;
				connection.address = peer.address().address;
				connection.port = peer.address().port;
				connection.fingerprint = fingerprint;

				callback(undefined, connection);
			});
		});

		peer.on("disconnect", function () {
			if (connecting) {
				setTimeout(function () {
					callback("connect-timeout");
				});
			}
			peer = undefined;
			connecting = false;
			if (typeof connection.onDisconnect === 'function') connection.onDisconnect.call();
		});

		connection.disconnect = function () {
			if (peer) peer.disconnectLater();
			peer = undefined;
		};

		connection.connected = function () {
			return (peer ? peer.state() === enet.PEER_STATE.CONNECTED : false);
		};
	};

	client.close = function () {
		setTimeout(function () {
			host.stop();
			host = undefined;
		}, 100);
	};

	return client;
};


function setupStreams(peer, options, fingerprint, callback) {
	var chan0 = peer.createDuplexStream(0);
	var remote = options.account.contact(uuid.v4());
	var session = remote.openSession({
		policy: otr.POLICY.ALWAYS
	});

	//internally handle OTR fragments from network and inject fragments to network
	var fragments = otrFragmentsStream(session);

	chan0.pipe(fragments).pipe(chan0);

	peer.on("disconnect", function () {
		chan0.unpipe(fragments);
		fragments.unpipe(chan0);
		fragments.end();
	});

	chan0.on("error", function (e) {
		//console.error("error on channel0:", e);
	});

	function terminate(reason) {
		session.end();
		peer.disconnectLater();
		callback(reason);
	}

	session.on("gone_secure", function () {
		clearTimeout(goSecureTimeout);
		//todo client access-control on fingerprint

		//client verifies fingerprint of server..
		if (options.client && fingerprint) {
			if (fingerprint !== session.theirFingerprint()) {
				terminate("invalid-server-fingerprint");
				return;
			}
		}

		//setup extra symmetric keys for AES stream - each side will tell the other they wish to use the extra symmetric key
		//which will result in two, keys being computed, one for sending and one for receiving.
		var sendingKey = session.extraSymKey(1, 'transport');

		var extraKeyTimeout = setTimeout(function () {
			terminate("otr-extra-key-timeout");
		}, 10000);

		session.on("received_symkey", function (use, usedata, receivingKey) {
			clearTimeout(extraKeyTimeout);
			if (sendingKey && receivingKey && use === 1) {
				callback(undefined, session.theirFingerprint(), otrMessagesStream(session, peer),
					aesStream(peer,
						sendingKey, receivingKey));
			} else {
				terminate("aes-keys-not-exchanged");
			}
		});

	});

	if (options.client) {
		session.start(); //client starts otr protocol
	}

	var goSecureTimeout = setTimeout(function () {
		terminate("otr-timeout");
	}, 30000);
}

function aesStream(peer, sendingKey, receivingKey) {
	var chan1 = peer.createDuplexStream(1);
	var stream = new Stream.Duplex();

	//review http://tools.ietf.org/html/rfc3686 to do proper AES stream encryption
	var encrypt = new EncryptStream(sendingKey.toString());
	var decrypt = new DecryptStream(receivingKey.toString());

	chan1.on("error", function (e) {
		//console.error("error on channel1:", e);
	});

	peer.on("disconnect", function () {
		stream.push(null);
		stream.end();
	});

	encrypt.pipe(chan1).pipe(decrypt);

	stream._write = function (buf, enc, next) {
		if (peer.state() === enet.PEER_STATE.CONNECTED) {
			encrypt.write(buf);
			next();
			return;
		}
		next("peer-not-connected");
	};

	stream._read = function () {};

	decrypt.on("data", function (buf) {
		stream.push(buf);
	});

	return stream;

}

function otrMessagesStream(session, peer) {
	var s = new Stream.Duplex();

	s._write = function (buf, enc, next) {
		if (peer.state() !== enet.PEER_STATE.CONNECTED) {
			next("peer-not-connected");
			return;
		}
		if (!session.isEncrypted()) {
			next("otr-session-ended");
			return;
		}
		session.send(buf);
		next();
	};

	s._read = function () {};

	session.on("disconnect", function () {
		s.push(null);
		s.end();
	});

	peer.on("disconnect", function () {
		session.end();
		s.push(null);
		s.end();
	});

	session.on("message", function (msg, encrypted) {
		if (encrypted) {
			s.push(msg);
		}
	});

	s.on("finish", function () {
		s.push(null);
		if (peer.state() === enet.PEER_STATE.CONNECTED) session.end();
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
			console.log("error generating key:", err);
		} else {
			user.saveKeysToFS(keys);
			account.generateInstag();
		}
		callback(account);
	});
};
