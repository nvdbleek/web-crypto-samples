var bleeken = bleeken || {};
bleeken.sample = bleeken.sample || {};
bleeken.sample.chat = (function() {
	var chat = {
		version : "1.0"
	};

	var crypto = window.crypto || window.msCrypto;
	
	var privateKey = null;
	var publicKey = null;
	
	var publicKeyOtherParty = null;

	chat.generateKeyPair = function() {
		var genOp = crypto.subtle.generateKey(
		        { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([0x01, 0x00, 0x01]) },
		        true,
		        ["encrypt", "decrypt"]);
		genOp.onerror = function(e) {
			$('#logContainer').append('<div class="text-danger">Error generating key pair</div>');
		}
		genOp.oncomplete = function(e) {
			publicKey = e.target.result.publicKey;
			privateKey = e.target.result.privateKey;

			if (publicKey && privateKey) {
				$('#logContainer').append('<div class="text-muted">Generated key pair</div>');
				
				var exportOp = crypto.subtle.exportKey("jwk", publicKey);
		        
				exportOp.onerror = function (evt) { 
					$('#logContainer').append('<div class="text-danger">Error exporting public key</div>'); 
				}
				exportOp.oncomplete = function (evt) {
			      pubKeyData = new Uint8Array(evt.target.result);
			      if (pubKeyData) {
			    	  $('#logContainer').append('<div class="text-muted">Exported public key</div>'); 
			    	  $('#publicKey').text(Base64Binary.encodeArrayBuffer(pubKeyData));
			      }
			      else {
			    	  $('#logContainer').append('<div class="text-danger">Error exporting public key</div>'); 
			      }
			    }
				
				
			} else {
				$('#logContainer').append('<div class="text-danger">Error generating key pair</div>');
			} // if-else
		} // genOp.oncomplete
	};
	
	chat.addPublicKeyOtherParty = function (data) {
		var importOp = crypto.subtle.importKey("jwk", Base64Binary.decodeArrayBuffer(data), { name: "RSAES-PKCS1-v1_5" }, false, ["decrypt"]);
        
		importOp.onerror = function (evt) { 
			$('#logContainer').append('<div class="text-danger">Error importing public key other party</div>'); 
		}
		importOp.oncomplete = function (evt) {
			publicKeyOtherParty = evt.target.result;
			if (publicKeyOtherParty) {
				$('#logContainer').append('<div class="text-muted">Imported public key other party</div>'); 
			}
			else {
				$('#logContainer').append('<div class="text-danger">Error importing public key other party</div>'); 
			}
	    }
	};
	
	chat.encrypt = function (data) {
		if (publicKeyOtherParty == null) {
			$('#logContainer').append('<div class="text-danger">Public key of other party is missing</div>');
		}
		
		var encryptOp = crypto.subtle.encrypt({ name: "RSAES-PKCS1-v1_5" }, publicKeyOtherParty, chat.str2ab(data));
		encryptOp.onerror = function (evt) {
			$('#logContainer').append('<div class="text-danger">Error encrypting data</div>');
        }

        encryptOp.oncomplete = function (evt) {
          encryptedData = evt.target.result;
          
          if (encryptedData) {
        	  $('#logContainer').append('<div class="text-muted">Encrypted data</div>');
        	  $('#encryptedMessage').text(Base64Binary.encodeArrayBuffer(encryptedData));
          } else {
        	  $('#logContainer').append('<div class="text-danger">Error encrypting data</div>');
          }

        }; // encryptOp.oncomplete
	};
	
	chat.decrypt = function (data) {
		if (privateKey == null) {
			$('#logContainer').append('<div class="text-danger">Keypair isn\'t generated</div>');;
		}
		
		var decryptOp = crypto.subtle.decrypt({ name: "RSAES-PKCS1-v1_5" }, privateKey, Base64Binary.decodeArrayBuffer(data));
		decryptOp.onerror = function (evt) {
			$('#logContainer').append('<div class="text-danger">Error decrypting data</div>');
		}
		
		decryptOp.oncomplete = function (evt) {
			decryptedData = evt.target.result;
			
			if (decryptedData) {
				$('#logContainer').append('<div class="text-muted">Decrypted data</div>');
				$('#decryptedMessageOther').text(chat.ab2str(decryptedData));
			} else {
				$('#logContainer').append('<div class="text-danger">Error decrypting data</div>');
			}
			
		}; // decryptOp.oncomplete
	};
	
	chat.hasGeneratedKeys = function() {
		return privateKey != null;
	};
	
	chat.ab2str = function (buf) {
	  return String.fromCharCode.apply(null, new Uint8Array(buf));
	}

	chat.str2ab = function (str) {
		var buf = new ArrayBuffer(str.length);
		var bufView = new Uint8Array(buf);
		for (var i=0, strLen=str.length; i<strLen; i++) {
			bufView[i] = str.charCodeAt(i);
		}
		return buf;
	}
	
	
	// Hook up event listeners
	$('#generatekeyPair').click(function() {
		bleeken.sample.chat.generateKeyPair();			
	});
	
	$('#publicKeyOtherParty').change(function() {
		bleeken.sample.chat.addPublicKeyOtherParty($('#publicKeyOtherParty').val());
	});
	
	$('#message').keyup(function() {
		bleeken.sample.chat.encrypt($('#message').val());			
	});
	
	$('#messageOther').keyup(function() {
		bleeken.sample.chat.decrypt($('#messageOther').val());			
	});

	return chat;
})();
