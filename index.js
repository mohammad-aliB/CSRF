'use strict';

const crypto = require('crypto');

exports.generateToken=function(domain,sessionID,CSRF_Store,res,callback){
    var sessionID=sessionID.replace(/[^a-z0-9]/g,"")
    crypto.randomBytes(48, function(err, buffer) {
        var CSRFToken = buffer.toString('hex');
        if(sessionID!==null&&sessionID==""){
            crypto.randomBytes(48, function(err, buffer) {
                SessionID = buffer.toString('hex');
                CSRF_Store.insert({"Domain":domain,"SessionID": SessionID, "CSRFToken": CSRFToken, "Used":0})   
                var d = new Date(); 
                d.setFullYear(d.getFullYear() + 10);
                res.writeHead(200, {'Set-Cookie': 'sessionID='+SessionID+'; Expires='+d+"; HttpOnly;"})
                return callback(CSRFToken)
            });
        }else{
            SessionID=sessionID.replace(/[^a-z0-9]/g,"")
            CSRF_Store.insert({"Domain":domain,"SessionID": SessionID, "CSRFToken": CSRFToken,"Used":0})
            return callback(CSRFToken)
        }
    });
}
exports.validateToken=function(domain,CSRF_Store,reqheaders,sessionID,CSRFToken,callback){
    var sessionID=sessionID.replace(/[^a-z0-9]/g,"")
    var CSRFToken=CSRFToken.replace(/[^a-z0-9]/g,"")
    if(reqheaders.host&&reqheaders.host==domain){
        if(reqheaders.origin&&reqheaders.origin=="https://"+domain){
            if(CSRFToken&&sessionID){
                CSRF_Store.update({"Domain":domain,"SessionID": sessionID,"CSRFToken":CSRFToken, "Used":0}, function(err, document) {
                    if (err){throw err;}
                    if (document.n==1){
                        callback(1);
                    }else{
                        callback(0);
                    }
                });
            }else{
                callback(0);
            }
        }else{
            callback(0);
        }
    }else{
        callback(0);
    }
}