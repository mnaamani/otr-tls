var transport = require("otr-tls");

transport.use("otr4-em");

transport.id({name:'client'},function(id){

 client = transport.createClient({
     "name":"client",
     "id": id,
     "connect": function(streams,ipaddress,port,fingerprint){
        //process.stdin.pipe(streams.otr_out);
        //streams.otr_in.pipe(process.stdout);
        process.stdin.pipe(streams.aes_out);
        streams.aes_in.pipe(process.stdout);
    }
  }).connect("127.0.0.1",6666);
});
