// // Required Modules
// const EC = require('elliptic').ec;
// const ec = new EC('secp256k1');
// const keccak256 = require('js-sha3').keccak256;
// const EthCrypto = require('eth-crypto');

// console.log('\n')

// // Private Key and Public Ethereum address (from Ganache)

// // const privateKey = (24045752869012519408531238626654924306523810268531446333191444089446180980000).toString(16)
// // 352969f06581a400000000000000000000000000000000000000000000000000 // 64 
// // 352969F06581A4E2C89A6B4D1370260A135A3DCD199C9FD60F08414EC7DA0520
// const privateKey = "352969f06581a4e2c89a6b4d1370260a135a3dcd199c9fd60f08414ec7da0520";
// console.log(`privateKey : ${privateKey}`)

// console.log('\n')
// console.log('\n')

// // const secp256k1 = require('secp256k1')
// // const publicKey0 = secp256k1.publicKeyCreate(Buffer.from(privateKey, 'hex'), false).slice(1)

// // console.log(`publicKey0: ${publicKey0}`)

// // const givenPrivateKey = 'c87509a1c067bbde78beb793e6fa76530b6382a4c0241e5e4a9ec0a0f44dc0d3';
// // const givenEthAddress = '0x627306090abab3a6e1400e9345bc60c78a8bef57';

// // // Get secp256k1 generator point
// // const generatorPoint = ec.g;

// // // // Public Key Coordinates calculated via Elliptic Curve Multiplication
// // // PublicKeyCoordinates = privateKey * generatorPoint
// // const pubKeyCoordinates = generatorPoint.mul(privateKey);

// // // console.log(pubKeyCoordinates)

// // const x1 = pubKeyCoordinates.getX() // .toString('hex');
// // const y1 = pubKeyCoordinates.getY() // .toString('hex');

// // console.log(`x1: ${x1}`)
// // console.log(`y1: ${y1}`)

// // const x1hex = pubKeyCoordinates.getX().toString('hex');
// // const y1hex = pubKeyCoordinates.getY().toString('hex');

// // console.log(`x1hex: ${x1hex}`)
// // console.log(`y1hex: ${y1hex}`)



// // const publicKey2 = x1hex + y1hex;

// // console.log('publicKey2', publicKey2);

// // // Use Keccak-256 hash function to get public key hash
// // const hashOfPublicKey2 = keccak256(new Buffer(publicKey2, 'hex'));

// // console.log('hashOfPublicKey2', hashOfPublicKey2);

// // // Convert hash to buffer
// // const ethAddressBuffer2 = new Buffer(hashOfPublicKey2, 'hex');

// // // Ethereum Address is '0x' concatenated with last 20 bytes
// // // of the public key hash
// // const ethAddress2 = ethAddressBuffer2.slice(-20).toString('hex');
// // const ethAddressWithPrefix2 = `0x${ethAddress2}`;

// // console.log(`ethAddressWithPrefix2: ${ethAddressWithPrefix2}`)




// // console.log('\n')
// // console.log('\n')

// // const x = (55682122449914098018890241650675130782511026399930682614291424929557888163329).toString(16)
// // const y = (56081296091175366700223204828465269946594430585523782888093867462642891103470).toString(16)

// // // const x = "55682122449914098018890241650675130782511026399930682614291424929557888163329"
// // // const y = "56081296091175366700223204828465269946594430585523782888093867462642891103470"

// // // // const x = qx.toString(16);
// // // // const y = qy.toString(16);

// // console.log(`x: ${x}`)
// // console.log(`y: ${y}`)

// // // // const x = pubKeyCoordinates.getX().toString('hex');
// // // // const y = pubKeyCoordinates.getY().toString('hex');

// // // // Public Key = X and Y concatenated

// const x = '7b1af6e6beda15bab468bcee673b43203040b1f06df821ff67b25f592ce8de01'
// const y = '7bfce383ffc5177ddbf0720bf8f51d8584cfab6c5adeeebc898b7bd58dc61cee'
// const publicKey = x + y;

// console.log('\n')
// console.log('publicKey', publicKey);
// console.log('\n')

// // // Use Keccak-256 hash function to get public key hash
// const hashOfPublicKey = keccak256(new Buffer(publicKey, 'hex'));

// // console.log('hashOfPublicKey', hashOfPublicKey);

// // // Convert hash to buffer
// const ethAddressBuffer = new Buffer(hashOfPublicKey, 'hex');

// // // Ethereum Address is '0x' concatenated with last 20 bytes
// // // of the public key hash
// const ethAddress = ethAddressBuffer.slice(-20).toString('hex');
// const ethAddressWithPrefix = `0x${ethAddress}`;

// // // Ethereum Address derived from private key
// // // is equal to the given address
// console.log(`ethAddressWithPrefix; ${ethAddressWithPrefix}`);

// console.log('\n')

// // // 0x721a5E85142a736Bb78f2957Bb2CC03a6cB63445
// const publicKey1 = EthCrypto.publicKeyByPrivateKey("352969f06581a4e2c89a6b4d1370260a135a3dcd199c9fd60f08414ec7da0520");
// const address1 = EthCrypto.publicKey.toAddress(publicKey1);
// console.log(`address: ${address1}`) 
// console.log('\n')


// // // const publicKeyToAddress = require('ethereum-public-key-to-address')
// // // console.log(publicKeyToAddress(Buffer.from(publicKey, 'hex'))) // '0x90F8bf6A479f320ead074411a4B0e7944Ea8c9C1'
// // // console.log('\n')


// // 5568212244991409801889024165067513078251102639993068261429142492955788816332956081296091175366700223204828465269946594430585523782888093867462642891103470
// // 04e68acfc0253a10620dff706b0a1b1f1f5833ea3beb3bde2250d5f271f3563606672ebc45e0b7ea2e816ecb70ca03137b1c9476eec63d4632e990020b7b6fba39

// // 7b1af6e6beda14000000000000000000000000000000000000000000000000007bfce383ffc51800000000000000000000000000000000000000000000000000
// // 04e68acfc0253a10620dff706b0a1b1f1f5833ea3beb3bde2250d5f271f3563606672ebc45e0b7ea2e816ecb70ca03137b1c9476eec63d4632e990020b7b6fba39