cordova.define("com.mwt.RSA.RSA", function(require, exports, module) {
// cordova.define("com.mobileware.npciLib.secureComponent", function(require, exports, module) {
var argscheck = require('cordova/argscheck'),
    utils = require('cordova/utils'),
    exec = require('cordova/exec'),
    channel = require('cordova/channel');

var RSA = function() {};

RSA.encrypt = function(successCallback, errorCallback, options) {

    options = options || {};
    var getValue = argscheck.getValue;

    var input = getValue(options.input, "");

    var args = [input];

    exec(successCallback,errorCallback,"RSA","ACTION_RSA_ENCRYPT",args);
}

module.exports = RSA;
// });

});
