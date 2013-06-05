var enet = require("enet");
var otr = require("otr4-em");
var EventEmitter = require("events").EventEmitter;
var Stream = require("stream");

var DecryptStream = require('./cryptostream.js').DecryptStream;
var EncryptStream = require('./cryptostream.js').EncryptStream;

module.exports.createServer = function(options){
    var host;//enet host
    var server = {};//otr transport server

    console.log("Local Identity - DSA Fingerprint",options.id.fingerprint(options.name,"otr.transport"));

    server.listen = function(port,maxpeers){
        host = enet.createServer({
            address: new enet.Address("0.0.0.0",options.port || 6666),
            peers:options.maxpeers||32,
            channels:2,
            down:0,
            up:0
         });

        host.on("connect",function(peer,data){
            //todo access control check on peer.address().address() ip address...
            options.peer = peer;
            options.host = host;
            options.client = false;            
            var streams = secureStream(options);
            streams[0].on("open",function(fingerprint){
                options.connect.call(server,{
                    "otr":streams[0],
                    "aes":streams[1]
                },peer.address().address(),peer.address().port(),fingerprint);
            });
        });

        host.start(20);
    }

    return server;
};

module.exports.createClient = function(options){
    var host;//enet host
    var client = {};//otr transport client
    var _peer;
    
    console.log("Local Identity - DSA Fingerprint",options.id.fingerprint(options.name,"otr.transport"));
    
    client.connect = function(ip,port,server_fingerprint){
        //only create host once
        if(!host){
        host = enet.createClient({
            peers:1,
            channels:2,
            down:0,
            up:0
         });
        }
        if(_peer) return;//only one connection at a time!
        _peer = host.connect(new enet.Address(ip,port));
        _peer.on("connect",function(){
            options.peer = _peer;
            options.host = host;
            options.client = true;
            options.server_fingerprint = server_fingerprint;
            var streams = secureStream(options);
            streams[0].on("open",function(fingerprint){
                options.connect.call(client,{
                    "otr":streams[0],
                    "aes":streams[1]
                },_peer.address().address(),_peer.address().port(),fingerprint);
            });

        });
        host.start(20);
    }
    client.end = function(){
        host.destroy();
    };
    client.disconnect = function(){
        _peer.on("disconnect",function(){
            _peer = undefined;
        });
        _peer.disconnectLater();
    }
    return client;
};


function secureStream(options){
    var extraKeySending;
    var secured = false;
    var otr_stream = new Stream();
    var aes_notify = new EventEmitter();    

    var identity = options.id;
    var peer = options.peer;
    var host = options.host;
    var client = options.client;
    var targetFingerprint = options.server_fingerprint;

    var remoteFingerprint;
    var chan0_in  = host.createReadStream(peer,0);
    var chan0_out = host.createWriteStream(peer,0);
    var chan1_in  = host.createReadStream(peer,1);
    var chan1_out = host.createWriteStream(peer,1);
   
    var remote_endpoint = peer.address().address() + peer.address().port; //sha1(address+date.now)?
    var remote = identity.ConnContext(options.name,"otr.transport",remote_endpoint);
    var session = new otr.Session(identity,remote,{policy:otr.POLICY("ALWAYS")});

    //otr protocol runs on channel 0
    chan0_in.on("data",function(buf){
        session.recv(buf);
    });
    chan0_in.on("end",function(){
        stream.emit("end");
    });
    session.on("inject_message",function(msg){
        chan0_out.write(msg);
    });

    session.on("gone_secure",function(){
        if(secured) return;//secure connection re-established (happens if multiple connections to client with same DSA key and instag)

            //todo client access-control on fingerprint
            remoteFingerprint = remote.fingerprint();
            //client verifies fingerprint of server..
            if(client && targetFingerprint) {
                if(targetFingerprint !== remoteFingerprint) {
                    secured = false;
                    peer.disconnectNow();
                    return;
                }
            }
            //setup extra symmetric keys for AES stream - each side will tell the other they wish to use the extra symmetric key
            //which will result in two, keys being computed, one for sending and one for receiving.
            extraKeySending = session.extraSymKey(1,'transport');
            secured = true;
    });

    if(client){
        session.connect();    //client starts otr protocol
    }

    session.on("received_symkey",function(use,usedata,extraKeyReceiving){
        if(!secured) return;
        //just testing... look at recommended way to derive keys from (32bytes)
        //look at DTLS/TLS how to do a proper scheme
        var enc = new EncryptStream(extraKeySending.toString());
        var dec = new DecryptStream(extraKeyReceiving.toString());

        enc.on("data",function(buf){
            if(buf) chan1_out.write(buf);
        });

        enc.on("end",function(){
        });
 
        chan1_in.on("data",function(buf){
            dec.write(buf);
        });

        chan1_in.on("end",function(buf){
        });

        otr_stream.emit("open",remoteFingerprint);
        aes_notify.emit("open",dec,enc);
    });
    
    otr_stream.write = function(buf){
        session.send(buf);
    };
    session.on("message",function(msg,encrypted){
        if(!encrypted) {
            otr_stream.emit("end");
            secured = false;
            return;
        }
        otr_stream.emit("data",msg);
    });
    otr_stream.end = function(){
        session.close();
        peer.disconnectLater();
    };
    
    return ([otr_stream,     //otr stream (on channel 0)
            aes_notify  //notifier of aes encrypted streams (on channel 1)
        ]);
}


module.exports.id = function(options){
  //load existing vfs file with otr keys username and protocol = otr.transport
  //or generate a new one and return 
  //an otr.User
  var filename = options.file || "./id.vfs";
  var name = options.name || "default-id";
  var protocol = "otr.transport";
 
  var VFS = otr.VFS(filename).load();
  var identity = new otr.User({keys:'/id.keys',fingerprints:'/id.fp',instags:'/id.instags'});
  if(!identity.findKey(name,protocol)){
    console.log("generating new identity...");
    identity.generateKey(name,protocol,function(err){
        if(err){
            identity = undefined;
            console.error("error generating key:",err);
        }
    });
    if(identity) VFS.save();
   }

   if(identity){//create a new instag for this application instance
        identity.generateInstag(name,protocol,function(err,instag){
        });
   }
   return identity;
};
