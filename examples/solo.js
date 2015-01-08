var fs = require("fs");
var transport = require("../lib/transport");

transport.account({
    name: 'server'
}, function (account) {
    start_server(account);
});

transport.account({
    name: 'client'
}, function (account) {
    start_client(account);
});

function start_client(account) {
    var client = transport.createClient({
        name: "client",
        account: account,
        connect: function (streams, ipaddress, port, fingerprint) {
            console.log("connected");
            var file = fs.createReadStream(__filename);
            file.pipe(streams.aes_out);
            file.on("end", function () {
                console.log("file sent");
                client.disconnect();
            });
        }
    });
    client.connect("127.0.0.1", 6666);
}

function start_server(account) {
    var server = transport.createServer({
        name: "server",
        account: account,
        connect: function (streams, ipaddress, port, fingerprint) {
            console.log("client connected:", fingerprint, "from:", ipaddress, port);
            streams.aes_in.pipe(process.stdout);
            streams.aes_in.on("end", function () {
                process.exit();
            });
        },
        "acl_fingerprints": ['123abc....', '456def...'] /* TODO: implement fingerprint ACL */
    });
    server.listen(6666);
}
