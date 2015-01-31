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
		connect: function (streams, ipaddress, port, fingerprint) {
			console.log("accepted connection: %s:%s (%s)", ipaddress, port, fingerprint);
			//process.stdin.pipe(streams.otr).pipe(process.stdout);
			//process.stdin.pipe(streams.aes).pipe(process.stdout);
			streams.otr.pipe(process.stdout);
			streams.aes.pipe(process.stdout);

			streams.otr.on("end", function () {
				console.log("OTR stream ended with: %s:%s", ipaddress, port);
			});

			streams.aes.on("end", function () {
				console.log("AES stream ended with: %s:%s", ipaddress, port);
			});
		},
		acl_fingerprints: ['123abc', '456def'] //not functional yet
	});

	server.listen(function (err) {
		console.log(err || "server ready.");
	});
});
