var fs = require("fs");

var transport = require("otr-tls");
var id = transport.id;

var client = transport.createClient({
     "name":"client",
     "id": id({name:"client"})
    ,"connect": function(streams,ipaddress,port,fingerprint){
        process.stdin.pipe(streams.otr_out);
        streams.otr_in.pipe(process.stdout);
    }
});

client.connect("127.0.0.1",6666);
