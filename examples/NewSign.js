'use strict';
var crypto = require('crypto'),
    secp256k1 = require('secp256k1');

var OPS = {
    "OP_PUSHDATA1": 76,
    "OP_PUSHDATA2": 77,
    "OP_PUSHDATA4": 78,
    "OP_DUP": 118,
    "OP_HASH160": 169,
    "OP_EQUALVERIFY": 136,
    "OP_CHECKSIG": 172
};

var signTransaction = function(transaction, publicKey, privateKey) {
    var ripemd160Hash = ripemd160(sha256(publicKey));

    var chunks = [];
    chunks.push(uint8Buffer(OPS.OP_DUP));
    chunks.push(uint8Buffer(OPS.OP_HASH160));
    chunks.push(pushDataIntBuffer(ripemd160Hash.length));
    chunks.push(ripemd160Hash);
    chunks.push(uint8Buffer(OPS.OP_EQUALVERIFY));
    chunks.push(uint8Buffer(OPS.OP_CHECKSIG));

    transaction.vin[0].script = Buffer.concat(chunks);

    var i = 0, signedTransaction = Promise.resolve(clone(decodedTransaction));

    for (; i < inputs.length; i++) {
        (function(index) {
            signedTransaction = signedTransaction.then(function(signedTransaction) {
                console.log('Signing input: ' + index);

                return issuer.sign(decodedTransaction, index, inputs[index].redeemScript, false).then(function(currentIndexSignedTransaction) {
                    signedTransaction.vin[index].script = currentIndexSignedTransaction.vin[index].script

                    return signedTransaction
                });
            });
        })(i);
    }

    console.log('signed hex string', signedTransaction.toString('hex'));
};


// hexstring: 0100000001a85d392dfbb9c0e3b91de2853d2ece6e42be30cbcd98319a6835b86ae0b08eea0100000000ffffffff0200000000000000003176a914c1fe3d898175f021f827fed320408adebc266a4288ac1673706b710700000008010000274701000000000000007500000000000000003176a91442ecb7a618d3fe7dd2c57d3a1d81a2433a4a4c7c88ac1673706b710700000008010000274762000000000000007500000000
signTransaction({
    "txid" : "26c30320eff6b7cebf00204f015844f284bd27db391d7bb0486cbfe62d0ba653",
    "version" : 1,
    "locktime" : 0,
    "vin" : [
        {
            "txid" : "9a86f1c70487536c13a3f4ccfafa8785d6de1269e5a26a92c60ab497015c250d",
            "vout" : 0,
            "scriptSig" : {
                "asm" : "",
                "hex" : ""
            },
            "sequence" : 4294967295
        }
    ],
    "vout" : [
        {
            "value" : 0.00000000,
            "n" : 0,
            "scriptPubKey" : {
                "asm" : "OP_DUP OP_HASH160 0c03187759c243acf68ccae3d8b162f147733f49 OP_EQUALVERIFY OP_CHECKSIG 73706b718587fafaccf4a3136c538704c7f1869a0a00000000000000 OP_DROP",
                "hex" : "76a9140c03187759c243acf68ccae3d8b162f147733f4988ac1c73706b718587fafaccf4a3136c538704c7f1869a0a0000000000000075",
                "reqSigs" : 1,
                "type" : "pubkeyhash",
                "addresses" : [
                    "12dAReWRRCoaSEM2zaDbqtGZr3BT7G1kCBedGc"
                ]
            },
            "assets" : [
                {
                    "name" : "ABCDEF",
                    "issuetxid" : "9a86f1c70487536c13a3f4ccfafa8785d6de1269e5a26a92c60ab497015c250d",
                    "assetref" : "1725-267-34458",
                    "qty" : 1.00000000,
                    "raw" : 10,
                    "type" : "transfer"
                }
            ],
            "permissions" : [
            ],
            "items" : [
            ]
        },
        {
            "value" : 0.00000000,
            "n" : 1,
            "scriptPubKey" : {
                "asm" : "OP_DUP OP_HASH160 299c4a1b1bc4119af3839037909e79e35fb2e681 OP_EQUALVERIFY OP_CHECKSIG 73706b718587fafaccf4a3136c538704c7f1869ade03000000000000 OP_DROP",
                "hex" : "76a914299c4a1b1bc4119af3839037909e79e35fb2e68188ac1c73706b718587fafaccf4a3136c538704c7f1869ade0300000000000075",
                "reqSigs" : 1,
                "type" : "pubkeyhash",
                "addresses" : [
                    "16dBf8LiRVATb7NqSsqUgudxkAQEfC6vMrw8g4"
                ]
            },
            "assets" : [
                {
                    "name" : "ABCDEF",
                    "issuetxid" : "9a86f1c70487536c13a3f4ccfafa8785d6de1269e5a26a92c60ab497015c250d",
                    "assetref" : "1725-267-34458",
                    "qty" : 99.00000000,
                    "raw" : 990,
                    "type" : "transfer"
                }
            ],
            "permissions" : [
            ],
            "items" : [
            ]
        }
    ],
    "data" : [
    ]
}, Buffer.from('024f5a3f5e69e5ef66d2ca813f29d9d3a142366198686ee0b6b0f3b39dd213a6fc', 'hex'), Buffer.from('86bb3031b10430d5a099ff3ed186825ae255d11f783091f3135c27ad94e6b60e', 'hex'));

// result:
// 0100000001a85d392dfbb9c0e3b91de2853d2ece6e42be30cbcd98319a6835b86ae0b08eea010000006b483045022100c424fe2e42e9223ca5ddbfa6dc7fe4964997d16aa53910924aeca0a2330c87e002207710aaeb20845f8d08b78295b05f5c90c3cb96025d893f8c53345d677a1def18012102fdcee0919d98a318fb34318ab6645420252eadf5cbfe09f5c4cc07d58f22c628ffffffff0200000000000000003176a914c1fe3d898175f021f827fed320408adebc266a4288ac1673706b710700000008010000274701000000000000007500000000000000003176a91442ecb7a618d3fe7dd2c57d3a1d81a2433a4a4c7c88ac1673706b710700000008010000274762000000000000007500000000
// result RPC call:
// 0100000001a85d392dfbb9c0e3b91de2853d2ece6e42be30cbcd98319a6835b86ae0b08eea010000006a473044022032e6bffb014c0929d1aa0fb2a0eeeb37858ffe9bc44697f9a51fce2b41cb5695022025d72a36fd104d4a8666f3248d06b7456d3acd98be08de913577a6e25ae539e5012102fdcee0919d98a318fb34318ab6645420252eadf5cbfe09f5c4cc07d58f22c628ffffffff0200000000000000003176a914c1fe3d898175f021f827fed320408adebc266a4288ac1673706b710700000008010000274701000000000000007500000000000000003176a91442ecb7a618d3fe7dd2c57d3a1d81a2433a4a4c7c88ac1673706b710700000008010000274762000000000000007500000000

function toBuffer(transaction) {
    var chunks = [];

    chunks.push(uint32Buffer(transaction.version));
    chunks.push(varIntBuffer(transaction.vin.length));

    transaction.vin.forEach(function (txIn) {
        var hash = [].reverse.call(new Buffer(txIn.txid, 'hex'));
        chunks.push(hash);
        chunks.push(uint32Buffer(txIn.vout)); // index

        if (txIn.script != null) {
            chunks.push(varIntBuffer(txIn.script.length));
            chunks.push(txIn.script);
        } else {
            chunks.push(varIntBuffer(0));
        }

        chunks.push(uint32Buffer(txIn.sequence));
    });

    chunks.push(varIntBuffer(transaction.vout.length));
    transaction.vout.forEach(function (txOut) {
        chunks.push(uint64Buffer(txOut.value));

        var script = Buffer.from(txOut.scriptPubKey.hex, 'hex');

        chunks.push(varIntBuffer(script.length));
        chunks.push(script);
    });

    chunks.push(uint32Buffer(transaction.locktime));

    return Buffer.concat(chunks);
}

function pushDataIntBuffer(number) {
    var chunks = [];

    var pushDataSize = number < OPS.OP_PUSHDATA1 ? 1
        : number < 0xff ? 2
            : number < 0xffff ? 3
                : 5;

    if (pushDataSize === 1) {
        chunks.push(uint8Buffer(number));
    } else if (pushDataSize === 2) {
        chunks.push(uint8Buffer(OPS.OP_PUSHDATA1));
        chunks.push(uint8Buffer(number));
    } else if (pushDataSize === 3) {
        chunks.push(uint8Buffer(OPS.OP_PUSHDATA2));
        chunks.push(uint16Buffer(number));
    } else {
        chunks.push(uint8Buffer(OPS.OP_PUSHDATA4));
        chunks.push(uint32Buffer(number));
    }

    return Buffer.concat(chunks);
}

function varIntBuffer(number) {
    var chunks = [];

    var size = number < 253 ? 1
        : number < 0x10000 ? 3
            : number < 0x100000000 ? 5
                : 9;

    // 8 bit
    if (size === 1) {
        chunks.push(uint8Buffer(number));

        // 16 bit
    } else if (size === 3) {
        chunks.push(uint8Buffer(253));
        chunks.push(uint16Buffer(number));

        // 32 bit
    } else if (size === 5) {
        chunks.push(uint8Buffer(254));
        chunks.push(uint32Buffer(number));

        // 64 bit
    } else {
        chunks.push(uint8Buffer(255));
        chunks.push(uint64Buffer(number));
    }

    return Buffer.concat(chunks);
}

function uint8Buffer(number) {
    var buffer = new Buffer(1);
    buffer.writeUInt8(number, 0);

    return buffer;
}

function uint16Buffer(number) {
    var buffer = new Buffer(2);
    buffer.writeUInt16LE(number, 0);

    return buffer;
}

function uint32Buffer(number) {
    var buffer = new Buffer(4);
    buffer.writeUInt32LE(number, 0);

    return buffer;
}

function uint64Buffer(number) {
    var buffer = new Buffer(8);
    buffer.writeInt32LE(number & -1, 0);
    buffer.writeUInt32LE(Math.floor(number / 0x100000000), 4);

    return buffer;
}

function hash256 (buffer) {
    return sha256(sha256(buffer))
}

function ripemd160 (buffer) {
    return crypto.createHash('rmd160').update(buffer).digest()
}

function sha256 (buffer) {
    return crypto.createHash('sha256').update(buffer).digest()
}