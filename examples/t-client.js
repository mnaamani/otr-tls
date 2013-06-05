var fs = require("fs");

var transport = require("otr-tls");
var id = transport.id;

var client = transport.createClient({
     "name":"client",
     "id": id({name:"client"})
    ,"connect": function(streams,ipaddress,port,fingerprint){
        streams.aes.on("open",function(instream,outstream){
/*
            var file = fs.createReadStream(__filename);
            file.pipe(outstream);
            file.on("end",function(){
                console.log("file sent over aes stream");
            });
*/
            console.log("piping stdin to aes stream");
            process.stdin.pipe(outstream);

        });
        /*
        var file = fs.createReadStream(__filename);
        file.pipe(streams.otr);        
        file.on("end",function(){
            console.log("file sent over otr stream");
        });
        process.stdin.pipe(streams.otr);
        */

    }
});

client.connect("127.0.0.1",6666);
