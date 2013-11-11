var bleeken = bleeken || {};
bleeken.sample = bleeken.sample || {};
bleeken.sample.hash = (function() {
	var hash = {
		version : "1.0"
	};

	var webCrypto;
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
	
	hash.hash = function (data) {
		var digestOp = webCrypto.digest({ name: "SHA-256" }, new Uint8Array(bleeken.sample.utils.str2ab(data)));
		digestOp.onerror = function (evt) {
			bleeken.sample.utils.logError('Error hash data')
        }

        digestOp.oncomplete = function (evt) {
        	digestValue = evt.target.result;
          
          if (digestValue) {
        	  bleeken.sample.utils.logInfo('Hashed data')
        	  $('#hash').text(bleeken.sample.utils.abv2hex(digestValue));
          } else {
        	  bleeken.sample.utils.logError('Error hashing data')
          }

        }; // digestOp.oncomplete
	};
	
	$('#message').keyup(function() {
		bleeken.sample.hash.hash($('#message').val());			
	});
	
	return hash;
})();
