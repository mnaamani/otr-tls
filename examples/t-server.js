var transport = require("otr-tls");

transport.id({name:"server"},function(id){
  transport.createServer({
    "name":"server",
    "id": id,
    "connect": function(streams,ipaddress,port,fingerprint){
            console.log("client connected:",fingerprint,"from:",ipaddress,port);

            //streams.otr_in.pipe(process.stdout);
            //process.stdout.pipe(streams.otr_out);
            streams.aes_in.pipe(process.stdout);
            process.stdin.pipe(streams.aes_out);

    }
    ,"acl_fingerprints":['123abc','456def'] //not functional yet
  }).listen(6666);
});
