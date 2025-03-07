// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IAccount} from "./../interfaces/IAccount.sol";

/*
PackedIntent packs metadata of intent (sender, standard, lengths) into bytes
1. sender: address, 20-bytes
2. standard: address, 20-bytes
3. headerLength: uint16, 2-bytes
4. instructionLength: uint16, 2-bytes
5. signatureLength: uint16, 2-bytes
*/
library PackedIntent {
    function getSenderAndStandard(bytes calldata intent) external pure returns (address, address) {
        require(intent.length >= 40, "Intent too short");
        return (address(bytes20(intent[: 20])), address(bytes20(intent[20 : 40])));
    }

    function getLengths(bytes calldata intent) external pure returns (uint256, uint256, uint256) {
        require(intent.length >= 46, "Missing length section");
        return (
            uint256(uint16(bytes2(intent[40 : 42]))),
            uint256(uint16(bytes2(intent[42 : 44]))),
            uint256(uint16(bytes2(intent[44 : 46])))
        );
    }

    function getSignatureLength(bytes calldata intent) external pure returns (uint256) {
        require(intent.length >= 46, "Missing length section");
        return uint256(uint16(bytes2(intent[44 : 46])));
    }

    function getIntentLength(bytes calldata intent) external pure returns (uint256) {
        require(intent.length >= 46, "Missing length section");
        uint256 headerLength = uint256(uint16(bytes2(intent[40 : 42])));
        uint256 instructionLength = uint256(uint16(bytes2(intent[42 : 44])));
        uint256 signatureLength = uint256(uint16(bytes2(intent[44 : 46])));
        return headerLength + instructionLength + signatureLength + 46;
    }

    function getIntentLengthFromSection(bytes6 lengthSection) external pure returns (uint16 result) {
        assembly {
            let value := lengthSection
            let a := shr(240, value) // Extract first 2 bytes
            let b := and(shr(224, value), 0xFFFF) // Extract next 2 bytes
            let c := and(shr(208, value), 0xFFFF) // Extract last 2 bytes
            result := add(add(add(a, b), c), 46)
        }
    }
}
