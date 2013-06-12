var fs = require("fs");
var transport = require("otr-tls");

transport.id({name:'server'},function(id){
    start_server(id);
});

transport.id({name:'client'},function(id){
    start_client(id);
});

function start_client(id){
  var client = transport.createClient({
     "name":"client",
     "id": id,
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
  client.connect("127.0.0.1",6666);
}

function start_server(id){
  var server = transport.createServer({
     "name": "server",
     "id": id,
     "connect": function(streams,ipaddress,port,fingerprint){
        console.log("client connected:",fingerprint,"from:",ipaddress,port);
        streams.aes_in.pipe(process.stdout);
     },
     "acl_fingerprints":['123abc....','456def...'] /* TODO: implement fingerprint ACL */
  });
  server.listen(6666);
}
