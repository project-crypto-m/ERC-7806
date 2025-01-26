// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {PackedIntent} from "./../libraries/PackedIntent.sol";

contract SelfIntentParser {
    function parseSelfIntent(bytes calldata intent) external returns (
        uint16[] memory, address[] memory, uint256[] memory, bytes[] memory, bytes1[] memory
    ) {
        (uint256 hLen, uint256 iLen, uint256 sLen) = PackedIntent.getLengths(intent);

        bytes memory intentCopy = new bytes(intent.length);
        assembly {
            // Get the offset and length of the calldata array
            let offset := intent.offset
            let length := intent.length

            // Copy calldata to memory
            calldatacopy(add(intentCopy, 0x20), offset, length)
        }

        uint256 numIns = hLen / 2;
        uint16[] memory dLens = new uint16[](numIns);
        address[] memory destinations = new address[](numIns);
        uint256[] memory values = new uint256[](numIns);
        bytes[] memory dataSections = new bytes[](numIns);
        bytes1[] memory tests = new bytes1[](numIns);
        uint256 start = 78 + hLen; // skip (32-bytes offset, sender, standard, 3 x lengths, header)
        address dest;
        bool hasValue;
        uint256 value;
        uint16 dLen;
        bytes memory dataSection;
        bool success;
        bytes1 test;

        for (uint256 i = 0; i < hLen; i+=2) {
            assembly {
                let data := mload(add(add(intentCopy, 78), i)) // load intent[46 + i: 78 + i]
                // Extract the first 2 bytes (uint16)
                dLen := shr(240, data) // Shift right by 240 bits (256 - 16)

                data := mload(add(intentCopy, start))  // load intent[start - 32 : start]
                // first bytes20 is the destination address
                test := shl(160, data)
                hasValue := iszero(iszero(byte(20, data)))
                dest := shr(96, data)
            }
            dLens[i / 2] = dLen;
            destinations[i / 2] = dest;
            tests[i / 2] = test;

            // if amount is not zero, it will be a bytes32
            // then the last bytes(insLen) is the callData
            if (hasValue) {
                assembly {
                    value := mload(add(add(intentCopy, start), 21)) // load 32 bytes after 21 = address + bool

                    dataSection := mload(0x40)  // point data section to free memory pointer
                    // Store the length of the call data slice
                    mstore(dataSection, dLen)

                    let readPtr := add(intentCopy, add(start, 53)) // Start of the slice
                    let copyPtr := add(dataSection, 32) // Pointer to the result's data section
                    for { let j := 0 } lt(j, dLen) { j := add(j, 32) } {
                        mstore(add(copyPtr, j), mload(add(readPtr, j)))
                    }

                    // Update the free memory pointer
                    mstore(0x40, add(copyPtr, dLen))
                }
                values[i / 2] = value;
                dataSections[i / 2] = dataSection;
                start = start + 53 + dLen;
            } else {
                assembly {
                    dataSection := mload(0x40)  // point data section to free memory pointer
                    // Store the length of the call data slice
                    mstore(dataSection, dLen)

                    let readPtr := add(intentCopy, add(start, 21)) // Start of the slice
                    let copyPtr := add(dataSection, 32) // Pointer to the result's data section
                    for { let j := 0 } lt(j, dLen) { j := add(j, 32) } {
                        mstore(add(copyPtr, j), mload(add(readPtr, j)))
                    }

                // Update the free memory pointer
                    mstore(0x40, add(copyPtr, dLen))
                }
                values[i / 2] = uint256(0);
                dataSections[i / 2] = dataSection;
                start = start + 21 + dLen;
            }
        }

        return (dLens, destinations, values, dataSections, tests);
    }
}
