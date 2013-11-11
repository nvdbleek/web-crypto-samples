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

	hash.hash = function (data) {
		var digestOp = webCrypto.digest({ name: "SHA-256" }, new Uint8Array(bleeken.sample.utils.str2ab(data)));
		digestOp.onerror = function (evt) {
			logError('Error hash data')
        }

        digestOp.oncomplete = function (evt) {
        	digestValue = evt.target.result;
          
          if (digestValue) {
        	  logInfo('Hashed data')
        	  $('#hash').text(bleeken.sample.utils.abv2hex(digestValue));
          } else {
        	  logError('Error hashing data')
          }

        }; // digestOp.oncomplete
	};
	
	$('#message').keyup(function() {
		bleeken.sample.hash.hash($('#message').val());			
	});
	
	return hash;
})();
