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
		account: account,
		//todo pass this function as a callback paramter in client.connect() method
		//so we can handle timeouts...
		//and return one object with streams,address and fingerprint
		connect: function (streams, ipaddress, port, fingerprint) {
			console.log("connection established: %s:%s (%s)", ipaddress, port, fingerprint);
			process.stdin.pipe(streams.otr).pipe(process.stdout);
			//process.stdin.pipe(streams.aes).pipe(process.stdout);
		}
	});
	console.log("connecting...");
	client.connect("127.0.0.1", 6666);
});
