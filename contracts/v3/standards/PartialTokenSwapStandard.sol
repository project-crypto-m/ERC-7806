// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {MessageHashUtils} from "openzeppelin/utils/cryptography/MessageHashUtils.sol";
import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";
import {IERC20} from "openzeppelin/token/ERC20/IERC20.sol";
import {IStandard} from "./../interfaces/IStandard.sol";
import {ITokenRelayer} from "./../interfaces/ITokenRelayer.sol";
import {IAccount} from "./../interfaces/IAccount.sol";
import {PackedIntent} from "./../libraries/PackedIntent.sol";
import {AmountGatedStandard} from "./AmountGatedStandard.sol";
import {BaseTokenRelayer} from "./../BaseTokenRelayer.sol";

/*
PartialTokenSwapStandard

This standard allows sender to defines an order that swaps 2 tokens (native or ERC20). It is amount and time gated,
meaning the intent can only be executed before a timestamp (expiration) or before the amount is fulfilled.

The first 20 bytes of the `intent` is sender address.
The next 20 bytes of the `intent` is the standard address, which should be equal to address of this standard.
The following is the length section, containing 3 uint16 defining header length, instructions length and signature length.

The header is fixed to be 32 bytes long.
The first 1 byte (uint8) is either "0x0" or "0x1", representing partial order and full order.
The next 3 bytes (uint24) are a random salt to allow users placing the same order multiple times.
The following 8 bytes (uint64) are the timestamp in epoch seconds.
The last 20 bytes (address) are the solver of this intent.
- if the solver is the sender, then any body can relay the intent.
- if the solver is not the sender, then the sender needs to provide a signature as well and only a specific relayer can
execute this intent on-chain.

The instructions contains 3 main part.
The first 36 bytes are packed encoded (address, uint128) pair representing the token and maximum amount the sender is
willing to send out.
The next 36 bytes are packed encoded (address, uint128) pair representing the token and amount the sender will get back
when the out amount is at max.
The following 16 bytes (uint128) are the out token amount of this execution. Only partial order needs this and this field
is filled in by the solver.

The signature field is 65 bytes long if the intent solver is sender, 130 bytes long if the intent solver is not the sender.

This intent allows nested intents to follow it, the first byte (uint8) after the intent body defines the number of
nested intents. Then the first 2-bytes of each nested intent defines the total length of the corresponding intent.

When executing, the operations will be carried out in the following order
- mark amount
- transfer out token with amount to the relayer
- execute nested intents (if any)
- transfer in token back from the relayer
*/
contract PartialTokenSwapStandard is AmountGatedStandard, BaseTokenRelayer {
    using ECDSA for bytes32;

    string public constant ICS_NUMBER = "ICS6";
    string public constant DESCRIPTION = "Timed Hashed Pre-Delegated Partial ERC20 Token Swap Standard";
    string public constant VERSION = "0.1.0";
    string public constant AUTHOR = "hellohanchen";

    bytes4 public constant VALIDATION_DENIED = 0x00000000;
    bytes4 public constant VALIDATION_APPROVED = 0x00000001;
    bytes4 public constant VALIDATION_APPROVED_SENDER_ONLY = 0x00000002;

    bytes32 public immutable DOMAIN_SEPARATOR;
    bytes32 public immutable SIGNED_DATA_TYPEHASH;

    constructor() {
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("PartialTokenSwapStandard")),
                keccak256(bytes("0.1.0")),
                block.chainid,
                address(this)
            )
        );

        SIGNED_DATA_TYPEHASH = keccak256(
            "Order(bool isFullOrder,uint24 salt,uint64 expiration,address solver,address outToken,uint128 outAmount,address inToken,uint128 inAmount)"
        );
    }

    function validateUserIntent(bytes calldata intent) external view returns (bytes4) {
        (address sender, address addressVar) = PackedIntent.getSenderAndStandard(intent);
        require(addressVar == address(this), "Not this standard");
        (uint256 uintVar1, uint256 uintVar2, uint256 signatureLen) = PackedIntent.getLengths(intent);
        require(uintVar1 == 32, "Invalid header length");
        require(intent.length >= 78 + uintVar2 + signatureLen, "Not enough intent length");
        // isFullOrder
        bool booleanVar = bytes1(intent[46 : 47]) == bytes1(0x01);
        if (booleanVar) {
            require(uintVar2 == 72, "Invalid full order instruction length");
        } else {
            require(uintVar2 == 88, "Invalid partial order instruction length");
        }
        uint256 uintVar3 = 78 + uintVar2;
        require(signatureLen == 65 || signatureLen == 130, "Invalid signature length");

        // fetch header content
        // salt = uint24(bytes3(intent[48:50]));  // we don't need to parse salt
        uintVar1 = uint256(uint64(bytes8(intent[50 : 58])));
        // timestamp
        require(uintVar1 >= block.timestamp, "Intent expired");

        // validate out token instruction
        // after header
        addressVar = address(bytes20(intent[78 : 98]));
        // max out token amount
        uintVar1 = uint256(uint128(bytes16(intent[98 : 114])));
        // amount for this oder
        uintVar2 = booleanVar ? uintVar1 : uint256(uint128(bytes16(intent[150 : 166])));
        if (addressVar != address(0)) {
            bytes memory data;
            (booleanVar, data) = addressVar.staticcall(abi.encodeCall(IERC20.balanceOf, (sender)));
            if (!booleanVar || data.length != 32) {
                revert("Not ERC20 token");
            }
            require(abi.decode(data, (uint256)) >= uintVar2, "Insufficient token balance");
        } else {
            require(sender.balance >= uintVar2, "Insufficient eth balance");
        }

        // after outToken ins is the inToken instruction
        addressVar = address(bytes20(intent[114 : 134]));
        if (addressVar != address(0)) {
            bytes memory data;
            (booleanVar, data) = addressVar.staticcall(abi.encodeCall(IERC20.totalSupply, ()));
            if (!booleanVar || data.length != 32) {
                revert("Not ERC20 token");
            }
        }

        (uint8 uint8Var, uint256 hash) = _validateSignatures(sender, address(bytes20(intent[58 : 78])), intent, uintVar3);
        if (uint8Var == 0) {
            return VALIDATION_APPROVED_SENDER_ONLY;
        }
        if (uint8Var == 1) {
            require(signatureLen == 65, "Only 1 signature is needed");
        }
        require(this.getAmount(sender, hash) + uintVar2 <= uintVar1, "Order limit exceeded");

        // no need to validate nested intent as that should be validated separately
        return VALIDATION_APPROVED;
    }

    function unpackOperations(bytes calldata intent) external view returns (bytes4 code, bytes[] memory unpackedInstructions) {
        (address sender, address addressVar) = PackedIntent.getSenderAndStandard(intent);
        require(addressVar == address(this), "Not this standard");
        bool isFullOrder = bytes1(intent[46 : 47]) == bytes1(0x01);
        // signature offset
        uint256 lengthVar = isFullOrder ? 150 : 166;

        // fetch header content
        // salt = uint24(bytes3(intent[48:50]));  // we don't need to parse salt
        // timestamp
        require(uint256(uint64(bytes8(intent[50 : 58]))) >= block.timestamp, "Intent expired");
        (uint8 uint8Var, uint256 hash) = _validateSignatures(sender, address(bytes20(intent[58 : 78])), intent, lengthVar);
        // solver != address(0), this numUsedSig should only be 1 or 2
        require(uint8Var != 0, "Solver is not assigned");
        // total length of this intent
        lengthVar = uint8Var == 1 ? lengthVar + 65 : lengthVar + 130;
        // # of nested intents
        uint8Var = intent.length == lengthVar ? 0 : uint8(bytes1(intent[lengthVar : lengthVar + 1]));

        // total instructions = mark amount + transfer out + nestIntents execution (optional) + transfer in
        unpackedInstructions = new bytes[](3 + uint8Var);

        // out token instruction, send token to tx.origin (aka. relayer)
        addressVar = address(bytes20(intent[78 : 98]));
        // max amount
        uint256 uint256Var1 = uint256(uint128(bytes16(intent[98 : 114])));
        // out amount of this order
        uint256 uint256Var2 = isFullOrder ? uint256Var1 : uint256(uint128(bytes16(intent[150 : 166])));
        require(this.getAmount(sender, hash) + uint256Var2 <= uint256Var1, "Order limit exceeded");

        // first instruction is mark amount to prevent re-entry attack
        unpackedInstructions[0] = abi.encode(
            address(this), 0, abi.encodeCall(AmountGatedStandard.markAmount, (hash, uint256Var2)));

        // out token instruction
        if (addressVar == address(0)) {
            unpackedInstructions[1] = abi.encode(tx.origin, uint256Var2, "");
        } else {
            unpackedInstructions[1] = abi.encode(
                addressVar,
                uint256(0),
                abi.encodeCall(IERC20.transfer, (tx.origin, uint256Var2)));
        }

        addressVar = address(bytes20(intent[114 : 134]));
        // max in amount
        uint256 uint256Var3 = uint256(uint128(bytes16(intent[134 : 150])));
        // in token amount of this order
        uint256Var3 = isFullOrder ? uint256Var3 : uint256Var3 * uint256Var2 / uint256Var1;
        // can't take in 0 amount
        uint256Var3 = uint256Var3 > 0 ? uint256Var3 : 1;
        // max operation index
        uint256Var1 = unpackedInstructions.length - 1;
        if (addressVar == address(0)) {
            // transfer native token out from this standard address
            unpackedInstructions[uint256Var1] = abi.encode(
                address(this), uint256(0), abi.encodeCall(ITokenRelayer.transferEth, (uint256Var3)));
        } else {
            // transfer ERC20 token from tx.origin (aka relayer) through this standard
            unpackedInstructions[uint256Var1] = abi.encode(
                address(this), uint256(0), abi.encodeCall(
                    ITokenRelayer.transferERC20From, (tx.origin, addressVar, uint256Var3)));
        }

        // nested intents
        if (uint8Var > 0) {
            lengthVar += 1;
            // max nested intent execution operation index
            uint256Var1 -= 1;
            // start index of nested intent execution operation
            uint256Var2 = 2;
            // index of nested intent starts from 2 because 0 is markAmount, 1 is out token instruction
            while (uint256Var2 <= uint256Var1) {
                require(lengthVar + 46 <= intent.length, "Invalid nested intent");
                uint256Var3 = PackedIntent.getIntentLengthFromSection(bytes6(intent[lengthVar + 40 : lengthVar + 46]));
                // nested intent length
                sender = address(bytes20(intent[lengthVar : lengthVar + 20]));
                unpackedInstructions[uint256Var2] = abi.encode(
                    sender,
                    uint256(0),
                    abi.encodeCall(IAccount.executeUserIntent, (intent[lengthVar : lengthVar + uint256Var3])));
                lengthVar += uint256Var3;
                uint256Var2 ++;
            }
        }

        return (VALIDATION_APPROVED, unpackedInstructions);
    }

    function _validateSignatures(
        address sender, address solver, bytes calldata intent, uint256 indexVar
    ) internal view returns (uint8, uint256) {
        bytes32 intentHash = keccak256(
            abi.encode(
                SIGNED_DATA_TYPEHASH,
                bytes1(intent[46 : 47]) == bytes1(0x01), // isFullOrder
                uint24(bytes3(intent[47 : 50])), // salt
                uint64(bytes8(intent[50 : 58])), // expiration
                solver,
                address(bytes20(intent[78 : 98])), // outToken
                uint128(bytes16(intent[98 : 114])), // outAmount
                address(bytes20(intent[114 : 134])), // inToken
                uint128(bytes16(intent[134 : 150]))  // inAmount
            )
        );
        bytes32 messageHash = MessageHashUtils.toTypedDataHash(DOMAIN_SEPARATOR, intentHash);
        uint256 firstSigEnd = indexVar + 65;
        // first signature ends
        require(sender == messageHash.recover(intent[indexVar : firstSigEnd]), "Invalid sender signature");

        // solver is not determined, no need to check solver signature
        if (solver == address(0)) {
            return (0, uint256(intentHash));
        }

        // only 1 signature is needed if
        // 1. self-solved
        // 2. solver-relayed
        if (solver == sender || solver == tx.origin) {
            return (1, uint256(intentHash));
        }

        // solver signs with assigned relayer
        indexVar += 130;
        // second signature ends
        require(intent.length >= indexVar, "At least 2 signatures are needed to assign relayer");
        bytes32 solverHash = keccak256(abi.encode(intentHash, tx.origin));
        messageHash = MessageHashUtils.toEthSignedMessageHash(solverHash);
        if (solver == messageHash.recover(intent[firstSigEnd : indexVar])) {
            return (2, uint256(intentHash));
        }

        // otherwise, solver signs with relayer == address(0) and everyone can relay this intent
        solverHash = keccak256(abi.encode(intentHash, address(0)));
        messageHash = MessageHashUtils.toEthSignedMessageHash(solverHash);
        require(solver == messageHash.recover(intent[firstSigEnd : indexVar]), "Invalid solver signature");

        return (2, uint256(intentHash));
    }

    // -------------
    // The following methods will be removed after testing
    // -------------
    function sampleIntent(
        address sender, address solver, address relayer,
        address outTokenAddress, uint128 maxAmount, uint128 orderAmount,
        address inTokenAddress, uint128 maxInAmount
    ) external view returns (
        bytes memory intent, bytes32 intentHash, bytes32 solverHash
    ) {
        uint16 signatureLength = solver == address(0) || solver == relayer ? 65 : 130;
        bool isFullOrder = orderAmount == maxAmount;
        uint64 expiration = uint64((block.timestamp + 31536000) & 0xFFFFFFFFFFFFFFFF);
        bytes memory toSign = bytes.concat(
            bytes32(abi.encodePacked(isFullOrder, uint24(0), expiration, solver)),
            abi.encodePacked(outTokenAddress, maxAmount),
            abi.encodePacked(inTokenAddress, maxInAmount)
        );
        uint16 instructionLength = isFullOrder ? 72 : 88;

        intent = isFullOrder ?
        bytes.concat(bytes20(sender), bytes20(address(this)), bytes2(uint16(32)), bytes2(instructionLength), bytes2(signatureLength), toSign) :
        bytes.concat(bytes20(sender), bytes20(address(this)), bytes2(uint16(32)), bytes2(instructionLength), bytes2(signatureLength), toSign, bytes16(orderAmount));

        intentHash = keccak256(
            abi.encode(
                SIGNED_DATA_TYPEHASH,
                isFullOrder, // isFullOrder
                uint24(0), // salt
                expiration, // expiration
                solver,
                outTokenAddress, // outToken
                maxAmount, // outAmount
                inTokenAddress, // inToken
                maxInAmount  // inAmount
            )
        );
        solverHash = keccak256(abi.encode(intentHash, relayer));

        return (intent, intentHash, solverHash);
    }

    function sampleIntent2(
        address sender, address solver, address relayer,
        address outTokenAddress, uint128 maxAmount, uint128 orderAmount,
        address inTokenAddress, uint128 maxInAmount
    ) external view returns (
        bytes memory intent, bytes32 intentHash, bytes32 solverHash
    ) {
        uint16 signatureLength = solver == address(0) || solver == relayer ? 65 : 130;
        bool isFullOrder = orderAmount == maxAmount;
        uint64 expiration = uint64((block.timestamp + 31536000) & 0xFFFFFFFFFFFFFFFF);
        bytes memory toSign = bytes.concat(
            bytes32(abi.encodePacked(isFullOrder, uint24(0), expiration, solver)),
            abi.encodePacked(outTokenAddress, maxAmount),
            abi.encodePacked(inTokenAddress, maxInAmount)
        );
        uint16 instructionLength = isFullOrder ? 72 : 88;

        intent = isFullOrder ?
        bytes.concat(bytes20(sender), bytes20(address(this)), bytes2(uint16(32)), bytes2(instructionLength), bytes2(signatureLength), toSign) :
        bytes.concat(bytes20(sender), bytes20(address(this)), bytes2(uint16(32)), bytes2(instructionLength), bytes2(signatureLength), toSign, bytes16(orderAmount));

        intentHash = keccak256(
            abi.encode(
                SIGNED_DATA_TYPEHASH,
                isFullOrder, // isFullOrder
                uint24(0), // salt
                expiration, // expiration
                solver,
                outTokenAddress, // outToken
                maxAmount, // outAmount
                inTokenAddress, // inToken
                maxInAmount  // inAmount
            )
        );
        solverHash = keccak256(abi.encode(intentHash, relayer));

        return (intent, intentHash, solverHash);
    }

    function sampleCompoundIntent(
        bytes calldata origin,
        bytes[] calldata inners
    ) external pure returns (bytes memory) {
        bytes memory result = origin;
        uint8 size = uint8(inners.length);
        result = bytes.concat(result, bytes1(size));

        for (uint8 i = 0; i < size; i++) {
            result = bytes.concat(result, inners[i]);
        }

        return result;
    }

    function executeUserIntent(bytes calldata intent) external returns (bytes memory) {
        (address sender,) = PackedIntent.getSenderAndStandard(intent);
        bytes memory executeCallData = abi.encodeCall(IAccount.executeUserIntent, (intent));

        (, bytes memory result) = sender.call{value : 0, gas : gasleft()}(executeCallData);
        return result;
    }
}
