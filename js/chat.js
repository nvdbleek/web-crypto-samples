var bleeken = bleeken || {};
bleeken.sample = bleeken.sample || {};
bleeken.sample.chat = (function() {
	var chat = {
		version : "1.0"
	};

	var crypto = window.crypto || window.msCrypto;
	var privateKey = null;

	chat.generateKeyPair = function() {
		var genOp = crypto.subtle.generateKey(
		        { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([0x01, 0x00, 0x01]) },
		        false,
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
	
	chat.encrypt = function (data) {
		if (privateKey == null) {
			return;
		}
		
		var encryptOp = crypto.subtle.encrypt({ name: "RSAES-PKCS1-v1_5" }, privateKey, chat.str2ab(data));
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
	
	$('#message').keyup(function() {
		if (bleeken.sample.chat.hasGeneratedKeys()) {
			bleeken.sample.chat.encrypt($('#message').val());			
		}
	});
	
	return chat;
})();
