//SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.0;

import "hardhat/console.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/structs/EnumerableMap.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import "./EllipticCurve.sol";

contract Voted is Ownable {
    using EnumerableMap for EnumerableMap.AddressToUintMap;
    EnumerableMap.AddressToUintMap private users;
    uint public privateKey;
    string public publicKey;
    // uint public address;

    constructor() {
        generatePrivateKey();
        derivePubKey();
    }

    function generatePrivateKey() public /*returns (uint)*/ {
        // Could generate using chainlink in the future
        privateKey = uint(keccak256(abi.encodePacked("hello wrold")));
    }


    function substring(string memory str, uint startIndex, uint endIndex) public returns (string memory) {
        bytes memory strBytes = bytes(str);
        bytes memory result = new bytes(endIndex-startIndex);
        for(uint i = startIndex; i < endIndex; i++) {
            result[i-startIndex] = strBytes[i];
        }
        return string(result);
    }

    // source: https://github.com/witnet/elliptic-curve-solidity
    uint public constant GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint public constant GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;
    uint public constant AA = 0;
    uint public constant BB = 7;
    uint public constant PP = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;

    // x: 23007056334434277873064007289986791585149905606975921951318844578841290075836
    // y: 43734657687288629282229735894187801927062204745136220966237435241985306471099
    function derivePubKey() public  /*returns(uint qx, uint qy)*/ {
      (uint qx,  uint qy) = EllipticCurve.ecMul(
        privateKey,
        GX,
        GY,
        AA,
        PP
      );

      publicKey = string(abi.encodePacked(substring(Strings.toHexString(qx), 2, 66), substring(Strings.toHexString(qy), 2, 66)));
    }

    using ECDSA for bytes32;

    function _verify(bytes32 data, bytes memory signature, address account) internal pure returns (bool) {
        return data.toEthSignedMessageHash()
            .recover(signature) == account;
    }

    function mult(uint x, uint y) public view returns(uint) {
        return x * y;
    }



    function decrypt(bytes32 iv, bytes memory ephemPublicKey, bytes memory ciphertext, bytes memory mac) public returns (string memory ) {
    

        return "HI";
    }   

}

