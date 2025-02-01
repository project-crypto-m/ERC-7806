// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MessageHashUtils} from "openzeppelin/utils/cryptography/MessageHashUtils.sol";
import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";
import {IERC20} from "openzeppelin/token/ERC20/IERC20.sol";
import {IStandard} from "./../interfaces/IStandard.sol";
import {ITokenRelayer} from "./../interfaces/ITokenRelayer.sol";
import {IAccount} from "./../interfaces/IAccount.sol";
import {PackedIntent} from "./../libraries/PackedIntent.sol";
import {AmountGatedStandard} from "./AmountGatedStandard.sol";
import {BaseTokenRelayer} from "./../BaseTokenRelayer.sol";

contract PartialTokenSwapOrderIntent is AmountGatedStandard, BaseTokenRelayer {
    using ECDSA for bytes32;

    string public constant ICS_NUMBER = "ICS6";
    string public constant DESCRIPTION = "Timed Hashed Pre-Delegated Partial ERC20 Token Swap Standard";
    string public constant VERSION = "0.0.0";
    string public constant AUTHOR = "hellohanchen";

    bytes4 public constant VALIDATION_DENIED = 0x00000000;
    bytes4 public constant VALIDATION_APPROVED = 0x00000001;
    bytes4 public constant VALIDATION_APPROVED_SENDER_ONLY = 0x00000002;
    bytes4 public constant ERC20_TRANSFER_SELECTOR = IERC20.transfer.selector;
    bytes4 public constant IACCOUNT_EXECUTE_USER_INTENT_SELECTOR = IAccount.executeUserIntent.selector;

    function validateUserIntent(bytes calldata intent) external view returns (bytes4) {
        (address sender, address addressVar) = PackedIntent.getSenderAndStandard(intent);
        require(addressVar == address(this), "Not this standard");
        (uint256 uintVar1, uint256 uintVar2, uint256 signatureLen) = PackedIntent.getLengths(intent);
        require(uintVar1 == 32, "Invalid header length");
        bool isFullOrder = bytes1(intent[46 : 47]) == bytes1(0x01);
        if (isFullOrder) {
            require(uintVar2 == 72, "Invalid full order instruction length");
        } else {
            require(uintVar2 == 88, "Invalid partial order instruction length");
        }
        uint256 uintVar3 = 78 + uintVar2;
        require(signatureLen == 65 || signatureLen == 130, "Invalid signature length");
        require(signatureLen + uintVar3 <= intent.length, "Not enough intent length");

        // fetch header content
        // nonce = uint32(bytes4(intent[47:50]));  // we don't need to parse nonce
        uintVar1 = uint256(uint64(bytes8(intent[50 : 58])));
        // timestamp
        require(uintVar1 >= block.timestamp, "Intent expired");

        // validate out token instruction
        addressVar = address(bytes20(intent[78 : 98]));
        // after header
        uintVar1 = uint256(uint128(bytes16(intent[98 : 114])));
        // max amount
        uintVar2 = isFullOrder ? uintVar1 : uint256(uint128(bytes16(intent[150 : 166])));
        // amount for this oder
        if (addressVar != address(0)) {
            try IERC20(addressVar).balanceOf(sender) returns (uint256 balance) {
                require(balance >= uintVar2, "Insufficient token balance");
            } catch {
                revert("Not ERC20 token");
            }
        } else {
            require(sender.balance >= uintVar2, "Insufficient eth balance");
        }

        addressVar = address(bytes20(intent[114 : 134]));
        // after outToken ins
        if (addressVar != address(0)) {
            // check if in token is ERC20
            try IERC20(addressVar).totalSupply() {
                // no op
            } catch {
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
        uint256 lengthVar = isFullOrder? 150 : 166;  // signature offset

        // fetch header content
        // nonce = uint32(bytes4(intent[47:50]));  // we don't need to parse nonce
        require(uint256(uint64(bytes8(intent[50 : 58]))) >= block.timestamp, "Intent expired");  // timestamp
        // because solver != address(0), this numUsedSig can only be 1 or 2
        (uint8 uintVar, uint256 hash) = _validateSignatures(sender, address(bytes20(intent[58 : 78])), intent, lengthVar);
        lengthVar = uintVar == 1 ? lengthVar + 65 : lengthVar + 130;  // total length of this intent
        uintVar = intent.length == lengthVar ? 0 : uint8(bytes1(intent[lengthVar: lengthVar + 1]));  // # of nested intents

        // total instructions = transfer out + nestIntents execution (optional) + transfer in + mark nonce
        unpackedInstructions = new bytes[](3 + uintVar);

        // out token instruction, send token to tx.origin (aka. relayer)
        addressVar = address(bytes20(intent[78 : 98]));
        uint256 maxAmount = uint256(uint128(bytes16(intent[98 : 114])));
        uint256 orderAmount = isFullOrder ? maxAmount : uint256(uint128(bytes16(intent[150 : 166])));
        require(this.getAmount(sender, hash) + orderAmount <= maxAmount, "Order limit exceeded");
        if (addressVar == address(0)) {
            unpackedInstructions[0] = abi.encode(address(tx.origin), orderAmount, "");
        } else {
            unpackedInstructions[0] = abi.encode(
                addressVar,
                uint256(0),
                abi.encodeWithSelector(ERC20_TRANSFER_SELECTOR, address(tx.origin), orderAmount));
        }

        addressVar = address(bytes20(intent[114 : 134]));
        uint256 uint256Var = uint256(uint128(bytes16(intent[134 : 150])));  // in amount of this order
        uint256Var = isFullOrder ? uint256Var : uint256Var * orderAmount / maxAmount;
        // can't take in 0 amount
        uint256Var = uint256Var > 0 ? uint256Var : 1;
        if (addressVar == address(0)) {
            // transfer native token out from this standard address
            unpackedInstructions[1 + uintVar] = abi.encode(
                address(this), uint256(0), abi.encodeWithSelector(ITokenRelayer.transferEth.selector, uint256Var));
        } else {
            // transfer ERC20 token from tx.origin (aka relayer) through this standard
            unpackedInstructions[1 + uintVar] = abi.encode(
                address(this), uint256(0), abi.encodeWithSelector(
                    ITokenRelayer.transferERC20From.selector, tx.origin, addressVar, uint256Var));
        }

        unpackedInstructions[2 + uintVar] = abi.encode(
            address(this), 0, abi.encodeWithSelector(this.markAmount.selector, hash, orderAmount));

        // nested intents
        if (uintVar > 0) {
            lengthVar += 1;
            uintVar = 1;  // index of nested intent starts from 1 because 0 is out token instruction
            while (uintVar <= unpackedInstructions.length - 3) {
                require(lengthVar + 46 <= intent.length, "Invalid nested intent");
                uint256Var = PackedIntent.getIntentLengthFromSection(bytes6(intent[lengthVar + 40 : lengthVar + 46]));  // nested intent length
                sender = address(bytes20(intent[lengthVar : lengthVar + 20]));
                unpackedInstructions[uintVar] = abi.encode(
                    sender,
                    uint256(0),
                    abi.encodeWithSelector(IACCOUNT_EXECUTE_USER_INTENT_SELECTOR, intent[lengthVar : lengthVar + uint256Var]));
                lengthVar += uint256Var;
                uintVar ++;
            }
        }

        return (VALIDATION_APPROVED, unpackedInstructions);
    }

    function _validateSignatures(
        address sender, address solver, bytes calldata intent, uint256 uintVar1
    ) internal view returns (uint8, uint256) {
        bytes32 intentHash = keccak256(abi.encode(intent[46 : 150], address(this), block.chainid));
        bytes32 messageHash = MessageHashUtils.toEthSignedMessageHash(intentHash);
        uint256 uintVar2 = uintVar1 + 65;  // first signature ends
        require(sender == messageHash.recover(intent[uintVar1 : uintVar2]), "Invalid sender signature");

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
        uintVar1 += 130;  // second signature ends
        require(intent.length >= uintVar1, "At least 2 signatures are needed to assign relayer");
        bytes32 solverHash = keccak256(abi.encode(intentHash, tx.origin));
        messageHash = MessageHashUtils.toEthSignedMessageHash(solverHash);
        if (solver == messageHash.recover(intent[uintVar2 : uintVar1])) {
            return (2, uint256(intentHash));
        }

        // otherwise, solver signs with relayer == address(0) and everyone can relay this intent
        solverHash = keccak256(abi.encode(intentHash, address(0)));
        messageHash = MessageHashUtils.toEthSignedMessageHash(solverHash);
        require(solver == messageHash.recover(intent[uintVar2 : uintVar1]), "Invalid solver signature");

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
        bytes memory toSign = bytes.concat(
            bytes32(abi.encodePacked(isFullOrder, uint24(0), uint64((block.timestamp + 31536000) & 0xFFFFFFFFFFFFFFFF), solver)),
            abi.encodePacked(outTokenAddress, maxAmount),
            abi.encodePacked(inTokenAddress, maxInAmount)
        );
        uint16 instructionLength = isFullOrder ? 72 : 88;

        intent = isFullOrder ?
            bytes.concat(bytes20(sender), bytes20(address(this)), bytes2(uint16(32)), bytes2(instructionLength), bytes2(signatureLength), toSign) :
            bytes.concat(bytes20(sender), bytes20(address(this)), bytes2(uint16(32)), bytes2(instructionLength), bytes2(signatureLength), toSign, bytes16(orderAmount));
        intentHash = keccak256(abi.encode(toSign, address(this), block.chainid));
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
        bytes memory toSign = bytes.concat(
            bytes32(abi.encodePacked(isFullOrder, uint24(0), uint64((block.timestamp + 31536000) & 0xFFFFFFFFFFFFFFFF), solver)),
            abi.encodePacked(outTokenAddress, maxAmount),
            abi.encodePacked(inTokenAddress, maxInAmount)
        );
        uint16 instructionLength = isFullOrder ? 72 : 88;

        intent = isFullOrder ?
            bytes.concat(bytes20(sender), bytes20(address(this)), bytes2(uint16(32)), bytes2(instructionLength), bytes2(signatureLength), toSign) :
            bytes.concat(bytes20(sender), bytes20(address(this)), bytes2(uint16(32)), bytes2(instructionLength), bytes2(signatureLength), toSign, bytes16(orderAmount));
        intentHash = keccak256(abi.encode(toSign, address(this), block.chainid));
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
        bytes memory executeCallData = abi.encodeWithSelector(IACCOUNT_EXECUTE_USER_INTENT_SELECTOR, intent);

        (, bytes memory result) = sender.call{value : 0, gas : gasleft()}(executeCallData);
        return result;
    }
}
