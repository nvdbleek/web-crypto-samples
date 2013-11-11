var bleeken = bleeken || {};
bleeken.sample = bleeken.sample || {};
bleeken.sample.sign = (function() {
	var sign = {
		version : "1.0"
	};

	var webCrypto;
	var jwkAsObject = false; // Some implementations want the jwk as an object others as a ByteArrayBuffer
	if (window.crypto && window.crypto.subtle) {
		webCrypto = window.crypto.subtle;
	}
	else if (window.msCrypto && window.msCrypto.subtle) {
		webCrypto = window.msCrypto.subtle;
	}
	else {
		webCrypto = window.polycrypt;
		jwkAsObject = true;
	}
	
	var privateKey = null;
	var publicKey = null;
	
	var publicKeyOtherParty = null;
	
	sign.generateKeyPair = function() {
		var genOp = webCrypto.generateKey(
		        { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([0x01, 0x00, 0x01]) },
		        true,
		        ["sign", "verify"]);
		genOp.onerror = function(e) {
			bleeken.sample.utils.logError('Error generating key pair');
			$('#loading').css('display', 'none');
		}
		genOp.oncomplete = function(e) {
			publicKey = e.target.result.publicKey;
			privateKey = e.target.result.privateKey;

			if (publicKey && privateKey) {
				bleeken.sample.utils.logInfo('Generated key pair')
				
				var exportOp = webCrypto.exportKey("jwk", publicKey);
		        
				exportOp.onerror = function (evt) { 
					bleeken.sample.utils.logError('Error exporting public key') 
				}
				exportOp.oncomplete = function (evt) {
				  var pubKeyDataBase64;
				  if (evt.target.result.constructor === ArrayBuffer) {
					  pubKeyDataBase64 = Base64Binary.encodeArrayBuffer(new Uint8Array(evt.target.result));
				  }
				  else {
					  evt.target.result.kty = "RSA";
					  evt.target.result.extractable = true;
					  pubKeyDataBase64 = Base64Binary.encodeArrayBuffer(bleeken.sample.utils.str2ab(JSON.stringify(evt.target.result)));
				  }
				  
			      if (pubKeyDataBase64) {
			    	  bleeken.sample.utils.logInfo('Exported public key') 
			    	  $('#publicKey').text(pubKeyDataBase64);
			      }
			      else {
			    	  bleeken.sample.utils.logError('Error exporting public key') 
			      }
			    }
				
				
			} else {
				bleeken.sample.utils.logError('Error generating key pair')
			} // if-else
			$('#loading').css('display', 'none');
		} // genOp.oncomplete
		$('#loading').css('display', 'inline');
	};
	
	sign.addPublicKeyOtherParty = function (data) {
		var dataDecoded = Base64Binary.decodeArrayBuffer(data);
		var alg;
		if (jwkAsObject) {
			var str = bleeken.sample.utils.ab2str(dataDecoded);
			str = str.charCodeAt(str.length - 1) === 0?str.substring(0, str.length - 1):str; // Remove trailing 0 character if present
			dataDecoded = JSON.parse(str);
			alg = "RSASSA-PKCS1-v1_5"; // TODO Fix polycript, this should be a dictionary
		}
		else {
			alg = { name: "RSASSA-PKCS1-v1_5" };
		}
		var importOp = webCrypto.importKey("jwk", dataDecoded, alg, false, ["sign", "verify"]);
        
		importOp.onerror = function (evt) { 
			bleeken.sample.utils.logError('Error importing public key other party') 
		}
		importOp.oncomplete = function (evt) {
			publicKeyOtherParty = evt.target.result;
			if (publicKeyOtherParty) {
				bleeken.sample.utils.logInfo('Imported public key other party') 
			}
			else {
				bleeken.sample.utils.logError('Error importing public key other party') 
			}
	    }
	};
	
	sign.sign = function (data) {
		if (privateKey == null) {
			bleeken.sample.utils.logError('Keypair isn\'t generated');
			return;
		}
		
		var signOp = webCrypto.sign({ name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, privateKey, new Uint8Array(bleeken.sample.utils.str2ab(data)));
		signOp.onerror = function (evt) {
			bleeken.sample.utils.logError('Error signing data')
        }

        signOp.oncomplete = function (evt) {
          signedData = evt.target.result;
          
          if (signedData) {
        	  bleeken.sample.utils.logInfo('signed data')
        	  $('#signature').text(Base64Binary.encodeArrayBuffer(signedData));
          } else {
        	  bleeken.sample.utils.logError('Error signing data')
          }

        }; // signOp.oncomplete
	};
	
	sign.verify = function (message, signature) {
		if (publicKeyOtherParty == null) {
			bleeken.sample.utils.logError('Public key of other party is missing');
			return;
		}
		
		var verifyOp = webCrypto.verify({ name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, publicKeyOtherParty, new Uint8Array(Base64Binary.decodeArrayBuffer(signature)), new Uint8Array(bleeken.sample.utils.str2ab(message)));
		verifyOp.onerror = function (evt) {
			bleeken.sample.utils.logError('Error verifying data')
		}
		
		verifyOp.oncomplete = function (evt) {
			verifyedData = evt.target.result;
			
			if (verifyedData) {
				bleeken.sample.utils.logInfo('Verified data');
				$('#signatureOther').addClass('signature-valid');
				$('#signatureOther').removeClass('signature-invalid');
			} else {
				$('#signatureOther').addClass('signature-invalid');
				$('#signatureOther').removeClass('signature-valid');
				bleeken.sample.utils.logError('Error verifying data')
			}
			
		}; // verifyOp.oncomplete
	};
	
	sign.hasGeneratedKeys = function() {
		return privateKey != null;
	};
	
	
	// Hook up event listeners
	$('#generatekeyPair').click(function() {
		bleeken.sample.sign.generateKeyPair();			
	});
	
	$('#publicKeyOtherParty').change(function() {
		bleeken.sample.sign.addPublicKeyOtherParty($('#publicKeyOtherParty').val());
	});
	
	$('#message').keyup(function() {
		bleeken.sample.sign.sign($('#message').val());			
	});
	
	$('#messageOther').keyup(function() {
		var message = $('#messageOther').val();
		var signature = $('#signatureOther').val();
		if (message != '' && signature != '') {
			bleeken.sample.sign.verify(message, signature);			
		}
		else {
			$('#signatureOther').removeClass('signature-invalid');
			$('#signatureOther').removeClass('signature-valid');
		}
	});

	$('#signatureOther').keyup(function() {
		var message = $('#messageOther').val();
		var signature = $('#signatureOther').val();
		if (message != '' && signature != '') {
			bleeken.sample.sign.verify(message, signature);			
		}
		else {
			$('#signatureOther').removeClass('signature-invalid');
			$('#signatureOther').removeClass('signature-valid');
		}
	});

	return sign;
})();
