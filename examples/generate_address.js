'use strict';

var path = require('path'),
    addressFactory = require(path.resolve(__dirname, '../lib/address'));
var pubKeyHashVersion = "0050cb6e",
    checksumValue = "eddcdabf",
    privateKeyVersion =  "800d661f";
console.log('public key hash version', pubKeyHashVersion);
console.log('checksum', checksumValue);
console.log('private key version', privateKeyVersion);

console.log('----');
var address = addressFactory.generateNew(pubKeyHashVersion, checksumValue);
console.log('address', address.address);
console.log('pubkey', address.publicKey.toString('hex'));
console.log('privatekey', address.privateKey.toString('hex'));
console.log('----');
/*var wif = address.toWIF(privateKeyVersion, checksumValue);
console.log('WIF', wif);

console.log('----');
console.log('address', addressFactory.fromWIF(wif, pubKeyHashVersion, privateKeyVersion, checksumValue).toString());
*/