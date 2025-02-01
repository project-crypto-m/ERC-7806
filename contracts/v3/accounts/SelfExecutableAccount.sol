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

        return executeOtherIntent(intent, standard);
    }

    function executeSelfIntent(bytes calldata intent) internal returns (bytes memory) {
        (uint256 headerLength, uint256 uintVar1,) = PackedIntent.getLengths(intent);
        require(intent.length == headerLength + uintVar1 + 46, "Lengths not match");
        // no signature

        uintVar1 = 78 + headerLength;
        // start pointer, skip (32-bytes offset, sender, standard, 3 x lengths, header)

        address dest;
        bytes1 hasValue;
        uint256 value;
        bool success;
        uint16 dataLength;
        bytes memory executeData;

        for (uint256 i = 0; i < headerLength; i += 2) {
            dataLength = uint16(bytes2(intent[46 + i : 48 + i]));
            dest = address(bytes20(intent[uintVar1 : uintVar1 + 20]));
            hasValue = bytes1(intent[uintVar1 + 20 : uintVar1 + 21]);
            if (hasValue == bytes1(0x01)) {
                (success,) = dest.call{
                    value : uint256(bytes32(intent[uintVar1 + 21 : uintVar1 + 53])),
                    gas : gasleft()
                }(intent[uintVar1 + 53 : uintVar1 + 53 + dataLength]);
                uintVar1 = uintVar1 + 53 + dataLength;
            } else {
                (success,) = dest.call{
                value : uint256(bytes32(intent[uintVar1 + 21 : uintVar1 + 53])),
                gas : gasleft()
                }(intent[uintVar1 + 21 : uintVar1 + 21 + dataLength]);
                uintVar1 = uintVar1 + 21 + dataLength;
            }

            if (!success) {
                revert ExecutionError();
            }
        }

        return new bytes(0);
    }

    function executeOtherIntent(bytes calldata intent, address standard) internal virtual returns (bytes memory);

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
            (sender,) = PackedIntent.getSenderAndStandard(intents[i]);
            insData = abi.encodeWithSelector(IAccount.executeUserIntent.selector, intents[i]);
            header = bytes.concat(header, bytes2(uint16((insData.length) & 0xFFFF)));
            instructions = bytes.concat(instructions, bytes20(sender), bytes1(0x00), insData);
        }

        if (ethToRelayer != 0) {
            header = bytes.concat(header, bytes2(0x00));
            instructions = bytes.concat(instructions, bytes20(tokenRelayer), bytes1(0x01), bytes32(ethToRelayer));
        }

        return bytes.concat(
            bytes20(account), // address
            bytes20(account), // standard
            bytes2(uint16((header.length) & 0xFFFF)), // header length
            bytes2(uint16((instructions.length) & 0xFFFF)), // instructions length
            bytes2(0x0000), // signature length
            header,
            instructions
        );
    }
}
