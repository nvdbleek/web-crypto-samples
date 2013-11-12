var bleeken = bleeken || {};
bleeken.sample = bleeken.sample || {};
bleeken.sample.hash = (function() {
	var hash = {
		version : "1.0"
	};

	function processDigest(digestValue) {
		if (digestValue) {
			bleeken.sample.utils.logInfo('Hashed data')
			$('#hash').text(bleeken.sample.utils.abv2hex(digestValue.constructor === ArrayBuffer?new Uint8Array(digestValue):digestValue));
		} else {
			bleeken.sample.utils.logError('Error hashing data')
		}
	}
	
	hash.hash = function (data) {
		var digestOp = bleeken.sample.utils.webCrypto.digest({ name: "SHA-256" }, new Uint8Array(bleeken.sample.utils.str2ab(data)));
		if (digestOp.then !== undefined) {
			// Promise API
			digestOp.then(processDigest, bleeken.sample.utils.logError.bind(bleeken.sample.utils,'Error hashing data'));
		}
		else {
			// Event based API
			digestOp.onerror = function (evt) {
				bleeken.sample.utils.logError('Error hash data')
			}
			
			digestOp.oncomplete = function (evt) {
				digestValue = evt.target.result;
				
				processDigest(digestValue);
			}; // digestOp.oncomplete
		}
	};
	
	$('#message').keyup(function() {
		bleeken.sample.hash.hash($('#message').val());			
	});
	
	return hash;
})();
