const { expect } = require("chai");
const { ethers } = require("hardhat");
var crypto = require("crypto");

describe("Voted", function () {
  let contract;
  let owner, address1;

  beforeEach(async () => {
    [owner, address1] = await ethers.getSigners();
    const Voted = await ethers.getContractFactory("Voted");
    contract = await Voted.deploy();
  });

  it("STuff", async function () {

    const EthCrypto = require('eth-crypto');

    // const privateKey = '352969f06581a4e2c89a6b4d1370260a135a3dcd199c9fd60f08414ec7da0520'
    // const publicKey = '7b1af6e6beda15bab468bcee673b43203040b1f06df821ff67b25f592ce8de017bfce383ffc5177ddbf0720bf8f51d8584cfab6c5adeeebc898b7bd58dc61cee'

    // private and public keys are generated on chain1! 
    const privateKey = (await contract.privateKey()).toHexString().substring(2,66)
    const publicKey = await contract.publicKey()

    console.log(`
      privateKey: ${privateKey}
      publicKey: ${publicKey}
    `)

    // encrypt a message off chain using eth crypto lib
    // Use the contract's public key so only the contract can decrypt!
    const signature = EthCrypto.sign(
      `0x${privateKey}`,
      EthCrypto.hash.keccak256(12345)
    );

    const payload = {
      message: 12345, // this our secret msg1!
      signature
    };

    const encrypted = await EthCrypto.encryptWithPublicKey(
      publicKey, // by encrypting with bobs publicKey, only bob can decrypt the payload with his privateKey
      JSON.stringify(payload) // we have to stringify the payload before we can encrypt it
    );

    const encryptedString = EthCrypto.cipher.stringify(encrypted);
    // console.log(`\n encryptedString: ${encryptedString} \n`)

    const encryptedObject = EthCrypto.cipher.parse(encryptedString);
    // console.log(encryptedObject)
    const encryptedBuffer = {
      iv: Buffer.from(encryptedObject.iv, 'hex'),
      ephemPublicKey: Buffer.from(encryptedObject.ephemPublicKey, 'hex'),
      ciphertext: Buffer.from(encryptedObject.ciphertext, 'hex'),
      mac: Buffer.from(encryptedObject.mac, 'hex')
    };

    // eth crpyto uses the lib under the hood
    const _eccrypto = require("eccrypto");
    var EC = require("elliptic").ec;
    var ec = new EC("secp256k1");

    var keyA = ec.keyFromPrivate(privateKey);
    var keyB = ec.keyFromPublic(encryptedBuffer.ephemPublicKey);
    var Px = keyA.derive(keyB.getPublic());
    Px = Buffer.from(Px.toArray())

    //  TRying this out ... i think we need to multiply the private key and ephemPublicKey
    // console.log(`0x${privateKey}`, `0x${encryptedObject.ephemPublicKey}`)
    // res = await contract.mult(`0x${privateKey}`, `0x${encryptedObject.ephemPublicKey}`);
    // console.log(res)

    // function KeyPair(ec, options) {
    // this.ec = ec;
    // this.priv = null;
    // this.pub = null;

    // // KeyPair(ec, { priv: ..., pub: ... })
    // if (options.priv)
    //   this._importPrivate(options.priv, options.privEnc);
    // if (options.pub)
    //   this._importPublic(options.pub, options.pubEnc);
    // }
    //   return pub.mul(this.priv).getX();
    

    // const Px = await _eccrypto.derive(Buffer.from(privateKey, 'hex'), encryptedBuffer.ephemPublicKey)
    console.log('\n')
    console.log('shared secret; ' + Px.toString("hex"))
    console.log('\n')

    // const privateKeyInt = parseInt(privateKey, 16);
    // const publicKeyInt = parseInt(publicKey, 16);

    // const shared = privateKeyInt * publicKeyInt
    // console.log(shared.toString(16))


    // const shared = await contract.mult(`0x${privateKey}`, `0x${publicKey}`);
    // console.log("\nshared")
    // console.log(shared)
    // console.log('\n')

    // assert(privateKey.length === 32, "Bad private key");
    // assert(isValidPrivateKey(privateKey), "Bad private key");
    function sha512(msg) {
      return crypto.createHash("sha512").update(msg).digest();
    }

    var hash = sha512(Px);
    var encryptionKey = hash.slice(0, 32);
    var macKey = hash.slice(32);
    var dataToMac = Buffer.concat([
      encryptedBuffer.iv,
      encryptedBuffer.ephemPublicKey,
      encryptedBuffer.ciphertext
    ]);
    function hmacSha256(key, msg) {
      return crypto.createHmac("sha256", key).update(msg).digest();
    }

    var realMac = hmacSha256(macKey, dataToMac);
    // assert(equalConstTime(encryptedBuffer.mac, realMac), "Bad MAC"); 

    function aes256CbcDecrypt(iv, key, ciphertext) {
      var cipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
      var firstChunk = cipher.update(ciphertext);
      var secondChunk = cipher.final();
      return Buffer.concat([firstChunk, secondChunk]);
    }

    const finalRes = aes256CbcDecrypt(encryptedBuffer.iv, encryptionKey, encryptedBuffer.ciphertext);
    console.log(`\n final res : ${finalRes} \n `)

    // const decrypted = await EthCrypto.decryptWithPrivateKey(
    //   privateKey,
    //   encryptedObject
    // );
    // const decryptedPayload = JSON.parse(decrypted);

    // // check signature
    // const senderAddress = EthCrypto.recover(
    //   decryptedPayload.signature,
    //   EthCrypto.hash.keccak256(decryptedPayload.message)
    // );

    // console.log(
    //   'Got message from ' +
    //   senderAddress +
    //   ': ' +
    //   decryptedPayload.message
    // );

    // res = await contract.encryptDecrypt('0x' + encryptedObject.ciphertext, privateKey)
    // console.log(res)


    // const encrypted = await EthCrypto.encryptWithPublicKey(
    //   bob.publicKey, // by encrypting with bobs publicKey, only bob can decrypt the payload with his privateKey
    //   JSON.stringify(payload) // we have to stringify the payload before we can encrypt it
    // );


    // const EthCrypto = require('eth-crypto');
//     const signature = EthCrypto.sign(
//     alice.privateKey,
//     EthCrypto.hash.keccak256(secretMessage)
// );
// const payload = {
//     message: secretMessage,
//     signature
// };
// const encrypted = await EthCrypto.encryptWithPublicKey(
//     bob.publicKey, // by encrypting with bobs publicKey, only bob can decrypt the payload with his privateKey
//     JSON.stringify(payload) // we have to stringify the payload before we can encrypt it
// );



  });
});
