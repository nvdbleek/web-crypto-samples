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
	
	var logContainer = $('#logContainer');
	
	function scrollLog() {
		logContainer.animate({ scrollTop: logContainer.prop("scrollHeight") - logContainer.height() }, 300);
	}
	
	function logError(msg) {
		logContainer.append('<div class="text-danger">' + msg + '</div>');
		scrollLog();
	}
	
	function logInfo(msg) {
		logContainer.append('<div class="text-muted">' + msg + '</div>');
		scrollLog();
	}

	chat.generateKeyPair = function() {
		var genOp = crypto.subtle.generateKey(
		        { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([0x01, 0x00, 0x01]) },
		        true,
		        ["encrypt", "decrypt"]);
		genOp.onerror = function(e) {
			logError('Error generating key pair')
		}
		genOp.oncomplete = function(e) {
			publicKey = e.target.result.publicKey;
			privateKey = e.target.result.privateKey;

			if (publicKey && privateKey) {
				logInfo('Generated key pair')
				
				var exportOp = crypto.subtle.exportKey("jwk", publicKey);
		        
				exportOp.onerror = function (evt) { 
					logError('Error exporting public key') 
				}
				exportOp.oncomplete = function (evt) {
			      pubKeyData = new Uint8Array(evt.target.result);
			      if (pubKeyData) {
			    	  logInfo('Exported public key') 
			    	  $('#publicKey').text(Base64Binary.encodeArrayBuffer(pubKeyData));
			      }
			      else {
			    	  logError('Error exporting public key') 
			      }
			    }
				
				
			} else {
				logError('Error generating key pair')
			} // if-else
		} // genOp.oncomplete
	};
	
	chat.addPublicKeyOtherParty = function (data) {
		var importOp = crypto.subtle.importKey("jwk", Base64Binary.decodeArrayBuffer(data), { name: "RSAES-PKCS1-v1_5" }, false, ["decrypt"]);
        
		importOp.onerror = function (evt) { 
			logError('Error importing public key other party') 
		}
		importOp.oncomplete = function (evt) {
			publicKeyOtherParty = evt.target.result;
			if (publicKeyOtherParty) {
				logInfo('Imported public key other party') 
			}
			else {
				logError('Error importing public key other party') 
			}
	    }
	};
	
	chat.encrypt = function (data) {
		if (publicKeyOtherParty == null) {
			logError('Public key of other party is missing')
		}
		
		var encryptOp = crypto.subtle.encrypt({ name: "RSAES-PKCS1-v1_5" }, publicKeyOtherParty, chat.str2ab(data));
		encryptOp.onerror = function (evt) {
			logError('Error encrypting data')
        }

        encryptOp.oncomplete = function (evt) {
          encryptedData = evt.target.result;
          
          if (encryptedData) {
        	  logInfo('Encrypted data')
        	  $('#encryptedMessage').text(Base64Binary.encodeArrayBuffer(encryptedData));
          } else {
        	  logError('Error encrypting data')
          }

        }; // encryptOp.oncomplete
	};
	
	chat.decrypt = function (data) {
		if (privateKey == null) {
			logError('Keypair isn\'t generated');
		}
		
		var decryptOp = crypto.subtle.decrypt({ name: "RSAES-PKCS1-v1_5" }, privateKey, Base64Binary.decodeArrayBuffer(data));
		decryptOp.onerror = function (evt) {
			logError('Error decrypting data')
		}
		
		decryptOp.oncomplete = function (evt) {
			decryptedData = evt.target.result;
			
			if (decryptedData) {
				logInfo('Decrypted data')
				$('#decryptedMessageOther').text(chat.ab2str(decryptedData));
			} else {
				logError('Error decrypting data')
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
