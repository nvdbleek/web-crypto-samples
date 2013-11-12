var bleeken = bleeken || {};
bleeken.sample = bleeken.sample || {};
bleeken.sample.encrypt = (function() {
	var encrypt = {
		version : "1.0"
	};

	var privateKey = null;
	var publicKey = null;

	var publicKeyOtherParty = null;

	encrypt.generateKeyPair = function() {
		var genOp = bleeken.sample.utils.webCrypto.generateKey({
			name : "RSAES-PKCS1-v1_5",
			modulusLength : 2048,
			publicExponent : new Uint8Array([ 0x01, 0x00, 0x01 ])
		}, true, [ "encrypt", "decrypt" ]);
		genOp.onerror = function(e) {
			bleeken.sample.utils.logError('Error generating key pair');
			$('#loading').css('display', 'none');
		}
		genOp.oncomplete = function(e) {
			publicKey = e.target.result.publicKey;
			privateKey = e.target.result.privateKey;

			if (publicKey && privateKey) {
				bleeken.sample.utils.logInfo('Generated key pair')

				var exportOp = bleeken.sample.utils.webCrypto.exportKey("jwk", publicKey);

				exportOp.onerror = function(evt) {
					bleeken.sample.utils.logError('Error exporting public key')
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
						bleeken.sample.utils.logInfo('Exported public key')
						$('#publicKey').text(pubKeyDataBase64);
					} else {
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

	encrypt.addPublicKeyOtherParty = function(data) {
		var dataDecoded = Base64Binary.decodeArrayBuffer(data);
		var alg;
		if (bleeken.sample.utils.jwkAsObject) {
			var str = bleeken.sample.utils.ab2str(dataDecoded);
			str = str.charCodeAt(str.length - 1) === 0?str.substring(0, str.length - 1):str; // Remove trailing 0 character if present
			dataDecoded = JSON.parse(str);
			alg = "RSAES-PKCS1-v1_5";
		}
		else {
			alg = { name: "RSAES-PKCS1-v1_5" };
		}
		var importOp = bleeken.sample.utils.webCrypto.importKey("jwk", dataDecoded, alg, false, [ "encrypt", "decrypt" ]);

		importOp.onerror = function(evt) {
			bleeken.sample.utils.logError('Error importing public key other party')
		}
		importOp.oncomplete = function(evt) {
			publicKeyOtherParty = evt.target.result;
			if (publicKeyOtherParty) {
				bleeken.sample.utils.logInfo('Imported public key other party')
			} else {
				bleeken.sample.utils.logError('Error importing public key other party')
			}
		}
	};

	encrypt.encrypt = function(data) {
		if (publicKeyOtherParty == null) {
			bleeken.sample.utils.logError('Public key of other party is missing')
		}
		
		//TODO fix polycrypt
		var alg;
		if (bleeken.sample.utils.jwkAsObject) {
			alg = "RSAES-PKCS1-v1_5"
		}
		else {
			alg = { name : "RSAES-PKCS1-v1_5" };
		}

		var encryptOp = bleeken.sample.utils.webCrypto.encrypt(alg, publicKeyOtherParty, new Uint8Array(bleeken.sample.utils.str2ab(data)));
		encryptOp.onerror = function(evt) {
			bleeken.sample.utils.logError('Error encrypting data')
		}

		encryptOp.oncomplete = function(evt) {
			encryptedData = evt.target.result;

			if (encryptedData) {
				bleeken.sample.utils.logInfo('Encrypted data')
				$('#encryptedMessage').text(
						Base64Binary.encodeArrayBuffer(encryptedData));
			} else {
				bleeken.sample.utils.logError('Error encrypting data')
			}

		}; // encryptOp.oncomplete
	};

	encrypt.decrypt = function(data) {
		if (privateKey == null) {
			bleeken.sample.utils.logError('Keypair isn\'t generated');
		}
		
		//TODO fix polycrypt
		var alg;
		if (bleeken.sample.utils.jwkAsObject) {
			alg = "RSAES-PKCS1-v1_5"
		}
		else {
			alg = { name : "RSAES-PKCS1-v1_5" };
		}

		var decryptOp = bleeken.sample.utils.webCrypto.decrypt(alg, privateKey, new Uint8Array(Base64Binary.decodeArrayBuffer(data)));
		decryptOp.onerror = function(evt) {
			bleeken.sample.utils.logError('Error decrypting data')
		}

		decryptOp.oncomplete = function(evt) {
			decryptedData = evt.target.result;

			if (decryptedData) {
				bleeken.sample.utils.logInfo('Decrypted data')
				$('#messageOther').text(
						bleeken.sample.utils.ab2str(decryptedData));
			} else {
				bleeken.sample.utils.logError('Error decrypting data')
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