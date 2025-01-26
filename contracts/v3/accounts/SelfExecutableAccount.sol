// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {PackedIntent} from "./../libraries/PackedIntent.sol";
import {IAccount} from "./../interfaces/IAccount.sol";

abstract contract SelfExecutableAccount is IAccount {
    error ExecutionError();

    function executeUserIntent(bytes calldata intent) external returns (bytes memory) {
        (address sender, address standard) = PackedIntent.getSenderAndStandard(intent);
        require(address(this) == sender, "Not intent sender");

        if (address(this) == tx.origin && address(this) == standard) {
            return executeSelfIntent(intent);
        }

        return this.executeOtherIntent(intent, standard);
    }

    function executeSelfIntent(bytes calldata intent) internal returns (bytes memory) {
        (uint256 hLen, uint256 iLen, uint256 sLen) = PackedIntent.getLengths(intent);
        require(sLen == 0, "Signature shouldn't be provided");
        require(intent.length == hLen + iLen + 46, "Lengths not match");

        bytes memory intentCopy = new bytes(intent.length);
        assembly {
            // Copy calldata to memory
            calldatacopy(add(intentCopy, 0x20), intent.offset, intent.length)
        }

        uint256 numIns = hLen / 2;
        uint256 start = 78 + hLen; // skip (32-bytes offset, sender, standard, 3 x lengths, header)
        address dest;
        bool hasValue;
        uint256 value;
        bool success;
        uint256 dLen;
        bytes memory executeData;

        for (uint256 i = 0; i < numIns; i++) {
            assembly {
                let data := mload(add(add(intentCopy, 78), i)) // load intent[46 + i: 78 + i]
                // Extract the first 2 bytes (uint16)
                dLen := shr(240, data) // Shift right by 240 bits (256 - 16)

                data := mload(add(intentCopy, start))  // load intent[start - 32 : start]
                // 21-th byte indicate whether there is an uint256 value
                hasValue := iszero(iszero(byte(20, data)))
                // first bytes20 is the destination address
                dest := shr(96, data)
            }

            if (hasValue) {
                assembly {
                    value := mload(add(add(intentCopy, start), 21)) // load 32 bytes after 21 = address + bool

                    executeData := mload(0x40)  // point execute data to free memory pointer
                    // Store the length of the call data slice
                    mstore(executeData, dLen)

                    let readPtr := add(intentCopy, add(start, 53)) // Start of the slice
                    let copyPtr := add(executeData, 32) // Pointer to the result's data section
                    for { let j := 0 } lt(j, dLen) { j := add(j, 32) } {
                        mstore(add(copyPtr, j), mload(add(readPtr, j)))
                    }

                    // Update the free memory pointer
                    mstore(0x40, add(copyPtr, dLen))
                }

                (success,) = dest.call{value : value, gas : gasleft()}(executeData);
                start = start + 53 + dLen;
            } else {
                assembly {
                    executeData := mload(0x40)
                    mstore(executeData, dLen)
                    let readPtr := add(intentCopy, add(start, 21)) // Start of the slice
                    let copyPtr := add(executeData, 32) // Pointer to the result's data section
                    for { let j := 0 } lt(j, dLen) { j := add(j, 32) } {
                        mstore(add(copyPtr, j), mload(add(readPtr, j)))
                    }
                    mstore(0x40, add(copyPtr, dLen))
                }

                (success,) = dest.call{value : 0, gas : gasleft()}(executeData);
                start = start + 21 + dLen;
            }

            if (!success) {
                revert ExecutionError();
            }
        }

        return new bytes(0);
    }

    function executeOtherIntent(bytes calldata intent, address standard) external virtual returns (bytes memory);

    function sampleSelfIntent(
        address account,
        bytes[] calldata intents,
        address tokenRelayer,
        uint256 ethToRelayer,
        bool transferBeforeExecute
    ) external pure returns (bytes memory) {
        bytes memory instructions;
        bytes memory header;
        bytes memory insData;
        address sender;

        if (ethToRelayer != 0 && transferBeforeExecute) {
            header = bytes.concat(header, bytes2(0x00));
            instructions = bytes.concat(instructions, bytes20(tokenRelayer), bytes1(0x01), bytes32(ethToRelayer));
        }

        for (uint256 i = 0; i < intents.length; i++) {
            (sender, ) = PackedIntent.getSenderAndStandard(intents[i]);
            insData = abi.encodeWithSelector(IAccount.executeUserIntent.selector, intents[i]);
            header = bytes.concat(header, bytes2(uint16((insData.length) & 0xFFFF)));
            instructions = bytes.concat(instructions, bytes20(sender), bytes1(0x00), insData);
        }

        if (ethToRelayer != 0) {
            header = bytes.concat(header, bytes2(0x00));
            instructions = bytes.concat(instructions, bytes20(tokenRelayer), bytes1(0x01), bytes32(ethToRelayer));
        }

        return bytes.concat(
            bytes20(account),  // address
            bytes20(account),  // standard
            bytes2(uint16((header.length) & 0xFFFF)),  // header length
            bytes2(uint16((instructions.length) & 0xFFFF)),  // instructions length
            bytes2(0x0000),  // signature length
            header,
            instructions
        );
    }
}
