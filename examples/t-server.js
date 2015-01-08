var transport = require("../lib/transport");

transport.account({
    name: "server"
}, function (account) {
    if (!account) {
        console.log("error-no account");
        return;
    }
    transport.createServer({
        name: "server",
        account: account,
        connect: function (streams, ipaddress, port, fingerprint) {
            console.log("client connected:", fingerprint, "from:", ipaddress, port);

            //streams.otr_in.pipe(process.stdout);
            //process.stdout.pipe(streams.otr_out);
            streams.aes_in.pipe(process.stdout);
            process.stdin.pipe(streams.aes_out);
        },
        acl_fingerprints: ['123abc', '456def'] //not functional yet
    }).listen(6666);
});
