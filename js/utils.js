var bleeken = bleeken || {};
bleeken.sample = bleeken.sample || {};
bleeken.sample.utils = (function() {
	var utils = {
		version : "1.0"
	};
	
	var logContainer = $('#logContainer');
	
	function scrollLog() {
		logContainer.animate({ scrollTop: logContainer.prop("scrollHeight") - logContainer.height() }, 300);
	}
	
	utils.logError = function (msg) {
		logContainer.append('<div class="text-danger">' + msg + '</div>');
		scrollLog();
	}
	
	utils.logInfo = function (msg) {
		logContainer.append('<div class="text-muted">' + msg + '</div>');
		scrollLog();
	}

	utils.ab2str = function (buf) {
	  return String.fromCharCode.apply(null, new Uint8Array(buf));
	}

	utils.str2ab = function (str) {
		var buf = new ArrayBuffer(str.length);
		var bufView = new Uint8Array(buf);
		for (var i=0, strLen=str.length; i<strLen; i++) {
			bufView[i] = str.charCodeAt(i);
		}
		return buf;
	}
	
	utils.abv2hex = function (abv) {
        var b = new Uint8Array(abv.buffer, abv.byteOffset, abv.byteLength);
        var hex = "";
        for (var i=0; i <b.length; ++i) {
            var zeropad = (b[i] < 0x10) ? "0" : "";
            hex += zeropad + b[i].toString(16);
        }
        return hex;
    }
	
	return utils;
})();
