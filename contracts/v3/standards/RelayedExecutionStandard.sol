// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {MessageHashUtils} from "openzeppelin/utils/cryptography/MessageHashUtils.sol";
import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";
import {IERC20} from "openzeppelin/token/ERC20/IERC20.sol";
import {IStandard} from "./../interfaces/IStandard.sol";
import {ITokenRelayer} from "./../interfaces/ITokenRelayer.sol";
import {IAccount} from "./../interfaces/IAccount.sol";
import {PackedIntent} from "./../libraries/PackedIntent.sol";
import {HashGatedStandard} from "./HashGatedStandard.sol";

/*
RelayedExecutionStandard

This standard allows sender to define a list of execution instructions and asks the relayer to execute
on chain on behalf of the sender. It is hash and time gated means the intent can only be executed before
a timestamp and can only be executed once.

The first 20 bytes of the `intent` is sender address.
The next 20 bytes of the `intent` is the standard address, which should be equal to address of this standard.
The following is the length section, containing 3 uint16 defining header length, instructions length and signature length.

The header is either 8 bytes long or 28 bytes long.
The 8-byte part is the timestamp in epoch seconds.
The optional 20-byte defines the assigned relayer address if the sender only wants a specific relayer to execute.

The instructions contains 2 main part.
The first 36 bytes is a packed encoded (address, uint128) pair representing the 'payment' that the sender will pay to the
relayer. It should be an ERC20 token.
The following 1-byte is an uint8 defining the number of instructions to execute.
The instructions are concatenated together, the first 2 bytes (uint16) defines the length of each instruction, the following
is the instruction body. Instructions should be abi.encode(address, uint256, bytes) which can directly be executed by
the sender account.

The signature field is always 65 bytes long. It contains the signed bytes.concat(header, instructions).
*/
contract RelayedExecutionStandard is HashGatedStandard {
    using ECDSA for bytes32;

    string public constant ICS_NUMBER = "ICS1";
    string public constant DESCRIPTION = "Timed Hashed Relayed Execution Standard";
    string public constant VERSION = "0.0.0";
    string public constant AUTHOR = "hellohanchen";

    bytes4 public constant VALIDATION_DENIED = 0x00000000;
    bytes4 public constant VALIDATION_APPROVED = 0x00000001;
    bytes4 public constant IACCOUNT_EXECUTE_USER_INTENT_SELECTOR = IAccount.executeUserIntent.selector;

    function validateUserIntent(bytes calldata intent) external view returns (bytes4) {
        (address sender, address addressVar) = PackedIntent.getSenderAndStandard(intent);
        require(addressVar == address(this), "Not this standard");
        (uint256 uint256Var1, uint256 uint256Var2, uint256 uint256Var3) = PackedIntent.getLengths(intent);
        require(uint256Var1 == 28 || uint256Var1 == 8, "Invalid header length");
        require(uint256Var2 >= 36, "Instructions too short");
        require(uint256Var3 == 65, "Invalid signature length");
        // end of instructions
        uint256Var2 = 46 + uint256Var1 + uint256Var2;
        require(uint256Var2 + uint256Var3 == intent.length, "Invalid intent length");

        // validate signature
        uint256 hash = _validateSignatures(sender, intent, uint256Var2);
        require(!this.checkHash(sender, hash), "Hash is already executed");

        // header contains expiration timestamp and assigned relayer (optional)
        require(uint256(uint64(bytes8(intent[46 : 54]))) >= block.timestamp, "Intent expired");
        // assignedRelayerAddress = address(intent[54:74]) [optional]

        // end of header section / begin of instruction section
        uint256Var1 = 46 + uint256Var1;
        // first 20 bytes of instruction is out token address
        uint256Var2 = uint256Var1 + 20;
        addressVar = address(bytes20(intent[uint256Var1 : uint256Var2]));
        // out token amount, use uint128 to shorten the intent
        uint256Var3 = uint256Var2 + 16;
        uint256Var1 = uint256(uint128(bytes16(intent[uint256Var2 : uint256Var3])));
        if (addressVar != address(0)) {
            (bool success, bytes memory data) = addressVar.staticcall(
                abi.encodeWithSelector(IERC20.balanceOf.selector, sender)
            );
            if (!success || data.length != 32) {
                revert("Not ERC20 token");
            }
            require(abi.decode(data, (uint256)) >= uint256Var1, "Insufficient token balance");
        } else {
            require(sender.balance >= uint256Var1, "Insufficient eth balance");
        }

        // end of outToken instruction
        uint256 numExecutions = uint256(uint8(bytes1(intent[uint256Var3 : uint256Var3 + 1])));
        // instruction index
        uint256Var1 = 0;
        // begin of the first instruction
        uint256Var3 = uint256Var3 + 1;
        uint256 instructionsEnd = intent.length - 65;

        while (uint256Var1 < numExecutions) {
            uint256Var2 = uint256Var3 + 2;
            require(uint256Var2 <= instructionsEnd, "Intent too short: instruction length");
            // end of this execution instruction
            uint256Var3 = uint256Var2 + uint256(uint16(bytes2(intent[uint256Var3 : uint256Var2])));
            require(uint256Var3 <= instructionsEnd, "Intent too short: single instruction");

            uint256Var1 += 1;
        }
        require(uint256Var3 == instructionsEnd, "Intent length doesn't match");

        return VALIDATION_APPROVED;
    }

    function unpackOperations(bytes calldata intent) external view returns (bytes4 code, bytes[] memory unpackedInstructions) {
        (address sender, address addressVar) = PackedIntent.getSenderAndStandard(intent);
        require(addressVar == address(this), "Not this standard");
        (uint256 uint256Var1, uint256 uint256Var2, uint256 uint256Var3) = PackedIntent.getLengths(intent);
        require(uint256Var1 == 28 || uint256Var1 == 8, "Invalid header length");
        require(uint256Var2 >= 36, "Instructions too short");
        require(uint256Var3 == 65, "Invalid signature length");
        // end of instructions
        uint256Var2 = 46 + uint256Var1 + uint256Var2;
        require(uint256Var2 + uint256Var3 == intent.length, "Invalid intent length");

        // fetch header content (timestamp, relayer address [optional])
        require(uint256(uint64(bytes8(intent[46 : 54]))) >= block.timestamp, "Intent expired");
        if (uint256Var1 == 28) {
            // assigned relayer
            addressVar = address(bytes20(intent[54 : 74]));
            require(tx.origin == addressVar, "Relayer not assigned");
        }

        uint256 uint256Var4 = _validateSignatures(sender, intent, uint256Var2);
        require(!this.checkHash(sender, uint256Var4), "Hash is already executed");

        // begin of instructions
        uint256Var1 = uint256Var1 + 46;
        // total instructions = mark hash + transfer token to relayer + executions
        // the first 36 bytes defines the payment to relayer
        // the next 1 byte defines the number of execution instructions
        uint256Var2 = uint256Var1 + 36;
        uint256Var3 = uint256Var2 + 1;
        unpackedInstructions = new bytes[](2 + uint8(bytes1(intent[uint256Var2 : uint256Var3])));
        // first instruction is mark hash to prevent re-entry attack
        unpackedInstructions[0] = abi.encode(
            address(this), 0, abi.encodeWithSelector(this.markHash.selector, uint256Var4));

        // the first 20 bytes of instructions is the out token address
        uint256Var2 = uint256Var1 + 20;
        addressVar = address(bytes20(intent[uint256Var1 : uint256Var2]));
        // amount
        uint256Var4 = uint256(uint128(bytes16(intent[uint256Var2 : uint256Var2 + 16])));
        // out token instruction
        if (addressVar == address(0)) {
            unpackedInstructions[1] = abi.encode(address(tx.origin), uint256Var4, "");
        } else {
            unpackedInstructions[1] = abi.encode(
                addressVar,
                uint256(0),
                abi.encodeWithSelector(IERC20.transfer.selector, address(tx.origin), uint256Var4));
        }

        // instruction index
        uint256Var1 = 2;
        // uint256Var3, end of outToken instruction
        // uint256Var4, end of instructions section
        uint256Var4 = intent.length - 65;

        while (uint256Var1 < unpackedInstructions.length) {
            // start of next execution instruction
            uint256Var2 = uint256Var3 + 2;
            require(uint256Var2 <= uint256Var4, "Intent too short: instruction length");
            // end of next execution instruction
            uint256Var3 = uint256Var2 + uint256(uint16(bytes2(intent[uint256Var3 : uint256Var2])));
            require(uint256Var3 <= uint256Var4, "Intent too short: single instruction");

            unpackedInstructions[uint256Var1] = intent[uint256Var2 : uint256Var3];

            uint256Var1 += 1;
        }
        require(uint256Var3 == uint256Var4, "Intent length doesn't match");

        return (VALIDATION_APPROVED, unpackedInstructions);
    }

    function _validateSignatures(
        address sender, bytes calldata intent, uint256 sigStartIndex
    ) internal view returns (uint256) {
        bytes32 intentHash = keccak256(abi.encode(intent[46 : sigStartIndex], address(this), block.chainid));
        bytes32 messageHash = MessageHashUtils.toEthSignedMessageHash(intentHash);
        require(sender == messageHash.recover(intent[sigStartIndex : sigStartIndex + 65]), "Invalid sender signature");

        return uint256(intentHash);
    }

    // -------------
    // The following methods will be removed after testing
    // -------------
    function sampleIntent(
        address sender, address relayer,
        address outTokenAddress, uint128 outAmount,
        bytes[] memory executions
    ) external view returns (
        bytes memory intent, bytes32 intentHash
    ) {
        bytes memory header = relayer == address(0) ?
            abi.encodePacked(uint64((block.timestamp + 31536000) & 0xFFFFFFFFFFFFFFFF)) :
            abi.encodePacked(uint64((block.timestamp + 31536000) & 0xFFFFFFFFFFFFFFFF), relayer);

        bytes memory instructions = bytes.concat(bytes20(outTokenAddress), bytes16(outAmount), bytes1(uint8(executions.length)));
        for (uint256 i = 0; i < executions.length; i++) {
            uint16 length = uint16(executions[i].length);
            instructions = bytes.concat(instructions, bytes2(length), executions[i]);
        }

        bytes memory toSign = bytes.concat(header, instructions);
        intentHash = keccak256(abi.encode(toSign, address(this), block.chainid));

        intent = bytes.concat(bytes20(sender), bytes20(address(this)), bytes2(uint16(header.length)), bytes2(uint16(instructions.length)), bytes2(uint16(65)), toSign);

        return (intent, intentHash);
    }

    function sampleERC20Execution(
        address token, address receiver, uint256 amount
    ) external pure returns (bytes memory) {
        if (token == address(0)) {
            return abi.encode(receiver, amount, "");
        }

        return abi.encode(token, uint256(0), abi.encodeWithSelector(IERC20.transfer.selector, address(receiver), amount));
    }

    function executeUserIntent(bytes calldata intent) external returns (bytes memory) {
        (address sender,) = PackedIntent.getSenderAndStandard(intent);
        bytes memory executeCallData = abi.encodeWithSelector(IACCOUNT_EXECUTE_USER_INTENT_SELECTOR, intent);

        (, bytes memory result) = sender.call{value : 0, gas : gasleft()}(executeCallData);
        return result;
    }
}
