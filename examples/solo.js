var fs = require("fs");
var transport = require("otr-tls");
var id = transport.id;

var client = transport.createClient({
     "name":"client",
     "id": id({name:"client"}),
     "connect": function(streams,ipaddress,port,fingerprint){
        console.log("connected");
        var file = fs.createReadStream(__filename);
        file.pipe(streams.aes_out);
        file.on("end",function(){
           console.log("file sent");
           client.disconnect();
        });
     }
});

var server = transport.createServer({
     "name": "server",
     "id": id({name:"server"}),
     "connect": function(streams,ipaddress,port,fingerprint){
  
        console.log("client connected:",fingerprint,"from:",ipaddress,port);
        streams.aes_in.pipe(process.stdout);
     },
     "acl_fingerprints":['123abc....','456def...'] /* TODO: implement fingerprint ACL */
});

server.listen(6666);

client.connect("127.0.0.1",6666);

