var transport = require("../lib/transport");

transport.account({
	name: 'client'
}, function (account) {
	if (!account) {
		console.log("error-no-account");
		return;
	}
	console.log("our fingerprint:", account.fingerprint());

	var client = transport.createClient({
		account: account
	});

	console.log("connecting...");

	client.connect("127.0.0.1:6666", function (err, connection) {
		if (err) {
			console.log("connect failed:", err);
			client.close();
			return;
		}
		console.log("connection established: %s:%s (%s)", connection.address, connection.port,
			connection.fingerprint);

		process.stdin.pipe(connection.otr).pipe(process.stdout);

		connection.otr.on("end", function () {
			console.log("OTR stream ended");
		});

		connection.otr.on("error", function (e) {
			console.log("OTR stream error:", e);
		});

	}, "" /*optional server fingerprint*/ );
});
