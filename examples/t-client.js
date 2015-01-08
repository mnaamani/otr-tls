var transport = require("../lib/transport");

transport.account({
	name: 'client'
}, function (account) {
	if (!account) {
		console.log("error-no account");
		return;
	}
	client = transport.createClient({
		name: "client",
		account: account,
		connect: function (streams, ipaddress, port, fingerprint) {
			process.stdin.pipe(streams.otr_out);
			streams.otr_in.pipe(process.stdout);
			//process.stdin.pipe(streams.aes_out);
			//streams.aes_in.pipe(process.stdout);
		}
	}).connect("127.0.0.1", 6666);
});
