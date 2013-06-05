var transport = require("otr-tls");
var id = transport.id;

var server = transport.createServer({
    "name":"server",
     "id": id({name:"server"})
    ,"connect": function(streams,ipaddress,port,fingerprint){
            console.log("client connected:",fingerprint,"from:",ipaddress,port);

//            streams.otr.pipe(process.stdout);

            streams.aes.on("open",function(instream,outstream){
                console.log("piping aes stream to stdout");
                instream.pipe(process.stdout);
            });

    }
    ,"acl_fingerprints":['123abc','456def'] //not functional yet
});

server.listen(6666);
