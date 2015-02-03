var transport = require("../lib/transport");

transport.account({
	name: "server"
}, function (account) {
	if (!account) {
		console.log("error-no account");
		return;
	}
	console.log("our fingerprint:", account.fingerprint());
	var server = transport.createServer({
		account: account,
		port: 6666,
		maxpeers: 32,
		//todo need to return a peer object - to manullay disconnect when dont processing streams
		//or should be disconnect when all streams end?
		onConnect: function (connection) {
			console.log("accepted connection from: %s:%s (%s)", connection.address, connection.port,
				connection.fingerprint);

			connection.otr.pipe(process.stdout);
			connection.aes.pipe(process.stdout);

			connection.otr.on("end", function () {
				console.log("OTR stream ended with: %s:%s", connection.address, connection.port);
			});

			connection.aes.on("end", function () {
				console.log("AES stream ended with: %s:%s", connection.address, connection.port);
			});

			connection.onDisconnect = function () {
				server.close();
			};
		},
		acl_fingerprints: ['123abc', '456def'] //not functional yet
	});

	server.listen(function (err) {
		console.log(err || "server ready.");
	});
});
