var bleeken = bleeken || {};
bleeken.sample = bleeken.sample || {};
bleeken.sample.encrypt = (function() {
	var encrypt = {
		version : "1.0"
	};

	var webCrypto;
	var jwkAsObject = false; // Some implementations want the jwk as an
	// object others as a ByteArrayBuffer
	if (window.crypto && window.crypto.subtle) {
		webCrypto = window.crypto.subtle;
	} else if (window.msCrypto && window.msCrypto.subtle) {
		webCrypto = window.msCrypto.subtle;
	} else {
		webCrypto = window.polycrypt;
		jwkAsObject = true;
	}

	var privateKey = null;
	var publicKey = null;

	var publicKeyOtherParty = null;

	var logContainer = $('#logContainer');

	function scrollLog() {
		logContainer.animate({
			scrollTop : logContainer.prop("scrollHeight")
					- logContainer.height()
		}, 300);
	}

	function logError(msg) {
		logContainer.append('<div class="text-danger">' + msg + '</div>');
		scrollLog();
	}

	function logInfo(msg) {
		logContainer.append('<div class="text-muted">' + msg + '</div>');
		scrollLog();
	}

	encrypt.generateKeyPair = function() {
		var genOp = webCrypto.generateKey({
			name : "RSAES-PKCS1-v1_5",
			modulusLength : 2048,
			publicExponent : new Uint8Array([ 0x01, 0x00, 0x01 ])
		}, true, [ "encrypt", "decrypt" ]);
		genOp.onerror = function(e) {
			logError('Error generating key pair')
		}
		genOp.oncomplete = function(e) {
			publicKey = e.target.result.publicKey;
			privateKey = e.target.result.privateKey;

			if (publicKey && privateKey) {
				logInfo('Generated key pair')

				var exportOp = webCrypto.exportKey("jwk", publicKey);

				exportOp.onerror = function(evt) {
					logError('Error exporting public key')
				}
				exportOp.oncomplete = function(evt) {
					var pubKeyDataBase64;
					if (evt.target.result.constructor === ArrayBuffer) {
						pubKeyDataBase64 = Base64Binary
								.encodeArrayBuffer(new Uint8Array(
										evt.target.result));
					} else if (typeof evt.target.result === 'object') {
						evt.target.result.kty = "RSA";
						evt.target.result.extractable = true;
						pubKeyDataBase64 = Base64Binary
								.encodeArrayBuffer(bleeken.sample.utils
										.str2ab(JSON
												.stringify(evt.target.result)));
					}
					if (pubKeyDataBase64) {
						logInfo('Exported public key')
						$('#publicKey').text(pubKeyDataBase64);
					} else {
						logError('Error exporting public key')
					}
				}

			} else {
				logError('Error generating key pair')
			} // if-else
		} // genOp.oncomplete
	};

	encrypt.addPublicKeyOtherParty = function(data) {
		var dataDecoded = Base64Binary.decodeArrayBuffer(data);
		var alg;
		if (jwkAsObject) {
			var str = bleeken.sample.utils.ab2str(dataDecoded);
			str = str.charCodeAt(str.length - 1) === 0?str.substring(0, str.length - 1):str; // Remove trailing 0 character if present
			dataDecoded = JSON.parse(str);
			alg = "RSAES-PKCS1-v1_5";
		}
		else {
			alg = { name: "RSAES-PKCS1-v1_5" };
		}
		var importOp = webCrypto.importKey("jwk", dataDecoded, alg, false, [ "encrypt", "decrypt" ]);

		importOp.onerror = function(evt) {
			logError('Error importing public key other party')
		}
		importOp.oncomplete = function(evt) {
			publicKeyOtherParty = evt.target.result;
			if (publicKeyOtherParty) {
				logInfo('Imported public key other party')
			} else {
				logError('Error importing public key other party')
			}
		}
	};

	encrypt.encrypt = function(data) {
		if (publicKeyOtherParty == null) {
			logError('Public key of other party is missing')
		}
		
		//TODO fix polycrypt
		var alg;
		if (jwkAsObject) {
			alg = "RSAES-PKCS1-v1_5"
		}
		else {
			alg = { name : "RSAES-PKCS1-v1_5" };
		}

		var encryptOp = webCrypto.encrypt(alg, publicKeyOtherParty, new Uint8Array(bleeken.sample.utils.str2ab(data)));
		encryptOp.onerror = function(evt) {
			logError('Error encrypting data')
		}

		encryptOp.oncomplete = function(evt) {
			encryptedData = evt.target.result;

			if (encryptedData) {
				logInfo('Encrypted data')
				$('#encryptedMessage').text(
						Base64Binary.encodeArrayBuffer(encryptedData));
			} else {
				logError('Error encrypting data')
			}

		}; // encryptOp.oncomplete
	};

	encrypt.decrypt = function(data) {
		if (privateKey == null) {
			logError('Keypair isn\'t generated');
		}
		
		//TODO fix polycrypt
		var alg;
		if (jwkAsObject) {
			alg = "RSAES-PKCS1-v1_5"
		}
		else {
			alg = { name : "RSAES-PKCS1-v1_5" };
		}

		var decryptOp = webCrypto.decrypt(alg, privateKey, new Uint8Array(Base64Binary.decodeArrayBuffer(data)));
		decryptOp.onerror = function(evt) {
			logError('Error decrypting data')
		}

		decryptOp.oncomplete = function(evt) {
			decryptedData = evt.target.result;

			if (decryptedData) {
				logInfo('Decrypted data')
				$('#messageOther').text(
						bleeken.sample.utils.ab2str(decryptedData));
			} else {
				logError('Error decrypting data')
			}

		}; // decryptOp.oncomplete
	};

	encrypt.hasGeneratedKeys = function() {
		return privateKey != null;
	};

	// Hook up event listeners
	$('#generatekeyPair').click(function() {
		bleeken.sample.encrypt.generateKeyPair();
	});

	$('#publicKeyOtherParty').change(
			function() {
				bleeken.sample.encrypt.addPublicKeyOtherParty($('#publicKeyOtherParty').val());
			});

	$('#message').keyup(function() {
		bleeken.sample.encrypt.encrypt($('#message').val());
	});

	$('#encryptedMessageOther').keyup(function() {
		bleeken.sample.encrypt.decrypt($('#encryptedMessageOther').val());
	});

	return encrypt;
})();