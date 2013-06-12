var enet = require("enet");
var otr;
var EventEmitter = require("events").EventEmitter;
var Stream = require("stream");

var DecryptStream = require('./cryptostream.js').DecryptStream;
var EncryptStream = require('./cryptostream.js').EncryptStream;

otr = loadOtrLib();

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

        host.on("connect",function(_peer,data){
            //todo access control check on peer.address().address() ip address...
            options.peer = _peer;
            options.host = host;
            options.client = false;            
            secureStream(options).on("ready",function(fingerprint,otr_in,otr_out,aes_in,aes_out){
                options.connect.call(server,{
                    "otr_in":otr_in,
                    "otr_out":otr_out,
                    "aes_in":aes_in,
                    "aes_out":aes_out
                    },_peer.address().address(),_peer.address().port(),fingerprint);
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
            secureStream(options).on("ready",function(fingerprint,otr_in,otr_out,aes_in,aes_out){
                options.connect.call(client,{
                    "otr_in":otr_in,
                    "otr_out":otr_out,
                    "aes_in":aes_in,
                    "aes_out":aes_out
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

    var otr_stream_out = new Stream();
    var otr_stream_in  = new Stream();

    otr_stream_out.writetable = true;
    otr_stream_out.readable = false;
    otr_stream_in.writetable = false;
    otr_stream_in.readable = true;

    var streams_notify = new EventEmitter();

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
        otr_stream_in.emit("end");
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
        var aes_stream_out = new EncryptStream(extraKeySending.toString());
        var aes_stream_in  = new DecryptStream(extraKeyReceiving.toString());

        aes_stream_out.on("data",function(buf){
            if(buf) chan1_out.write(buf);
        });

        aes_stream_out.on("end",function(){
        });
 
        chan1_in.on("data",function(buf){
            aes_stream_in.write(buf);
        });

        chan1_in.on("end",function(buf){
        });

        streams_notify.emit("ready",remoteFingerprint, otr_stream_in, otr_stream_out, aes_stream_in, aes_stream_out);
    });
    
    otr_stream_out.write = function(buf){
        session.send(buf);
    };

    session.on("message",function(msg,encrypted){
        if(!encrypted) {
            otr_stream_in.emit("end");
            secured = false;
            return;
        }
        otr_stream_in.emit("data",msg);
    });

    otr_stream_out.end = function(){
        session.close();
        peer.disconnectLater();
    };
    
    return streams_notify;
}


module.exports.id = function(options,callback){
  //load existing vfs file with otr keys username and protocol = otr.transport
  //or generate a new one and return 
  //an otr.User
  var filename = options.file || "./id.vfs";
  var name = options.name || "default-id";
  var protocol = "otr.transport";

  var VFS = otr.VFS? otr.VFS(filename).load() : undefined;
  var identity = new otr.User({keys:'./keys-'+name,fingerprints:'/tmp/id.fp',instags:'/tmp/id.instags.'+name});
  
  if(identity.findKey(name,protocol)){
        identity.generateInstag(name,protocol,function(err,instag){});
        callback(identity);
        return;
  }
  
  console.log("generating new identity...");
  identity.generateKey(name,protocol,function(err){
    if(err){
        identity = undefined;
        console.error("error generating key:",err);
    }
    if(identity && VFS) VFS.save();
    //create a new instag for this application instance
    if(identity){
        identity.generateInstag(name,protocol,function(err,instag){});
    }
    callback(identity);
  });
};

function loadOtrLib(){
    try{
        return require("otr4");
    }catch(e){
        try{return require("otr4-em")}catch(e){}
    }
}
