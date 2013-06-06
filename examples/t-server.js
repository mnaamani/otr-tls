var transport = require("otr-tls");
var id = transport.id;

var server = transport.createServer({
    "name":"server",
     "id": id({name:"server"})
    ,"connect": function(streams,ipaddress,port,fingerprint){
            console.log("client connected:",fingerprint,"from:",ipaddress,port);

            streams.otr_in.pipe(process.stdout);
            process.stdout.pipe(streams.otr_out);

    }
    ,"acl_fingerprints":['123abc','456def'] //not functional yet
});

server.listen(6666);
