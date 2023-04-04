const secp = require("ethereum-cryptography/secp256k1");
const { keccak256 } = require("ethereum-cryptography/keccak"); //from lesson 1
const { utf8ToBytes } = require("ethereum-cryptography/utils"); // same ^


function hashMessage(message) {         //hashes a message 
    return keccak256(utf8ToBytes(message));
}           
const hashedmessage = (message) => keccak256(Uint8Array.from(message)); 


async function signMessage(msg) {       //signs a message requires a private key 
    const messageHash = hashMessage(msg);
    return secp.sign(messageHash, PRIVATE_KEY, { recovered: true });
}

async function recoverKey(message, signature, recoveryBit) { //recoves a public key from signature(prob not needed)
    const messageHash = hashMessage(message);
    return secp.recoverPublicKey(messageHash, signature, recoveryBit);
}

function getAddress(publicKey) { // gets an address from a public key 
    // the first byte indicates whether this is in compressed form or not
    return keccak256(publicKey.slice(1)).slice(-20);
}



module.exports = {
    hashMessage,
    pubKeyToAddress,
    signatureToPubKey,
  };