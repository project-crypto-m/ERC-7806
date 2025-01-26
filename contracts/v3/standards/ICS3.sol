// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MessageHashUtils} from "openzeppelin/utils/cryptography/MessageHashUtils.sol";
import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";
import {IERC20} from "openzeppelin/token/ERC20/IERC20.sol";
import {IStandard} from "./../interfaces/IStandard.sol";
import {ITokenRelayer} from "./../interfaces/ITokenRelayer.sol";
import {IAccount} from "./../interfaces/IAccount.sol";
import {PackedIntent} from "./../libraries/PackedIntent.sol";
import {HashGatedStandard} from "./HashGatedStandard.sol";
import {BaseTokenRelayer} from "./../BaseTokenRelayer.sol";

contract ICS3 is HashGatedStandard, BaseTokenRelayer {
    using ECDSA for bytes32;

    string public constant ICS_NUMBER = "ICS3";
    string public constant DESCRIPTION = "Timed Hashed Pre-Delegated ERC20 Token Swap Standard";
    string public constant VERSION = "0.0.0";
    string public constant AUTHOR = "hellohanchen";

    bytes4 public constant VALIDATION_DENIED = 0x00000000;
    bytes4 public constant VALIDATION_APPROVED = 0x00000001;
    bytes4 public constant VALIDATION_APPROVED_SENDER_ONLY = 0x00000002;
    bytes4 public constant ERC20_TRANSFER_SELECTOR = IERC20.transfer.selector;
    bytes4 public constant IACCOUNT_EXECUTE_USER_INTENT_SELECTOR = IAccount.executeUserIntent.selector;

    function validateUserIntent(bytes calldata intent) external view returns (bytes4) {
        (address sender, address standard) = PackedIntent.getSenderAndStandard(intent);
        require(standard == address(this), "Not this standard");
        (uint256 hLen, uint256 iLen, uint256 sLen) = PackedIntent.getLengths(intent);
        require(hLen == 32, "Invalid header length");
        require(iLen == 104, "Invalid instruction length");
        require(sLen == 65 || sLen == 130, "Invalid signature length");
        require(sLen + 182 <= intent.length, "Not enough intent length");

        // fetch header content
        // nonce = uint32(bytes4(intent[46:50]));  // we don't need to parse nonce
        uint64 timestamp = uint64(bytes8(intent[50 : 58]));
        require(timestamp >= block.timestamp, "Intent expired");
        address solver = address(bytes20(intent[58 : 78]));

        // validate out token instruction
        address tokenAddress = address(bytes20(intent[78: 98]));  // after header
        uint256 amount = uint256(bytes32(intent[98 : 130]));
        if (tokenAddress != address(0)) {
            try IERC20(tokenAddress).balanceOf(sender) returns (uint256 balance) {
                require(balance >= amount, "Insufficient token balance");
            } catch {
                revert("Not ERC20 token");
            }
        } else {
            require(sender.balance >= amount, "Insufficient eth balance");
        }

        tokenAddress = address(bytes20(intent[130 : 150]));  // after outToken ins
        amount = uint256(bytes32(intent[150 : 182]));
        if (tokenAddress != address(0)) {
            // check if in token is ERC20
            try IERC20(tokenAddress).totalSupply() {
                // no op
            } catch {
                revert("Not ERC20 token");
            }
        }

        (uint8 numUsedSig, uint256 hash) = _validateSignatures(sender, solver, intent);
        if (numUsedSig == 0) {
            return VALIDATION_APPROVED_SENDER_ONLY;
        }
        if (numUsedSig == 1) {
            require(sLen == 65, "Only 1 signature is needed");
        }
        require(!this.checkHash(sender, hash), "Hash executed");

        if (intent.length == sLen + 182) {
            return VALIDATION_APPROVED;  // no more nested intent
        }

        require(sLen + 222 <= intent.length, "Invalid nested intent");
        // nested intent
        sender = address(bytes20(intent[sLen + 182 : sLen + 202]));
        standard = address(bytes20(intent[sLen + 202 : sLen + 222]));
        return IStandard(standard).validateUserIntent(intent[sLen + 222:]);
    }

    function unpackOperations(bytes calldata intent) external view returns (bytes4, bytes[] memory) {
        (address sender, address standard) = PackedIntent.getSenderAndStandard(intent);
        require(standard == address(this), "Not this standard");
        (, , uint256 sLen) = PackedIntent.getLengths(intent);

        // fetch header content
        // nonce = uint32(bytes4(intent[46:50]));  // we don't need to parse nonce
        uint64 timestamp = uint64(bytes8(intent[50 : 58]));
        require(timestamp >= block.timestamp, "Intent expired");
        address solver = address(bytes20(intent[58 : 78]));

        uint256 hasNestedIntent = intent.length == 182 + sLen ? 0 : 1;

        // total instructions = signed + nestIntent execution (optional) + mark nonce
        bytes[] memory unpackedInstructions = new bytes[](2 + hasNestedIntent + 1);

        // out token instruction, send token to tx.origin (aka. relayer)
        address tokenAddress = address(bytes20(intent[78: 98]));
        uint256 amount = uint256(bytes32(intent[98 : 130]));
        if (tokenAddress == address(0)) {
            unpackedInstructions[0] = abi.encode(address(tx.origin), amount, "");
        } else {
            unpackedInstructions[0] = abi.encode(
                tokenAddress,
                uint256(0),
                abi.encodeWithSelector(ERC20_TRANSFER_SELECTOR, address(tx.origin), amount));
        }

        tokenAddress = address(bytes20(intent[130 : 150]));
        amount = uint256(bytes32(intent[150 : 182]));
        if (tokenAddress == address(0)) {
            // transfer native token out from this standard address
            unpackedInstructions[1 + hasNestedIntent] = abi.encode(
                address(this), uint256(0), abi.encodeWithSelector(ITokenRelayer.transferEth.selector, amount));
        } else {
            // transfer ERC20 token from tx.origin (aka relayer) through this standard
            unpackedInstructions[1 + hasNestedIntent] = abi.encode(
                address(this), uint256(0), abi.encodeWithSelector(
                        ITokenRelayer.transferERC20From.selector, tx.origin, tokenAddress, amount));
        }

        // because solver != address(0), this numUsedSig can only be 1 or 2
        (uint8 numUsedSig, uint256 hash) = _validateSignatures(sender, solver, intent);
        require(!this.checkHash(sender, hash), "Hash executed already");

        // nested intent
        if (intent.length > sLen + 182) {
            require(sLen + 228 <= intent.length, "Invalid nested intent");
            sender = address(bytes20(intent[sLen + 182 : sLen + 202]));
            unpackedInstructions[1] = abi.encode(
                sender,
                uint256(0),
                abi.encodeWithSelector(IACCOUNT_EXECUTE_USER_INTENT_SELECTOR, intent[sLen + 182:]));
        }

        unpackedInstructions[2 + hasNestedIntent] = abi.encode(
            address(this), 0, abi.encodeWithSelector(this.markHash.selector, hash));

        return (VALIDATION_APPROVED, unpackedInstructions);
    }

    function _validateSignatures(
        address sender, address solver, bytes calldata intent
    ) internal view returns (uint8, uint256) {
        bytes32 intentHash = keccak256(abi.encode(intent[46:182], address(this), block.chainid));
        bytes32 messageHash = MessageHashUtils.toEthSignedMessageHash(intentHash);
        require(sender == messageHash.recover(intent[182:247]), "Invalid sender signature");

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
        require(intent.length >= 312, "At least 2 signatures are needed to assign relayer");
        bytes32 solverHash = keccak256(abi.encode(intentHash, tx.origin));
        messageHash = MessageHashUtils.toEthSignedMessageHash(solverHash);
        if (solver == messageHash.recover(intent[247 : 312])) {
            return (2, uint256(intentHash));
        }

        // otherwise, solver signs with relayer == address(0) and everyone can relay this intent
        solverHash = keccak256(abi.encode(intentHash, address(0)));
        messageHash = MessageHashUtils.toEthSignedMessageHash(solverHash);
        require(solver == messageHash.recover(intent[247 : 312]), "Invalid solver signature");

        return (2, uint256(intentHash));
    }

    // -------------
    // The following methods will be removed after testing
    // -------------
    function sampleIntent(
        address maker, address taker, address solver, address relayer,
        uint32 nonce,
        address outTokenAddress, uint256 outAmount,
        address inTokenAddress, uint256 inAmount
    ) external view returns (
        bytes memory makerIntent, bytes32 makerHash, bytes32 makerRelayerHash,
        bytes memory takerIntent, bytes32 takerHash, bytes32 takerRelayerHash
    ) {
        uint16 sLen = 130;
        if (solver == address(0) || solver == relayer) {
            sLen = 65;
        }

        bytes32 header = bytes32(abi.encodePacked(nonce, uint64((block.timestamp + 31536000) & 0xFFFFFFFFFFFFFFFF), solver));
        // TODO
        bytes memory makerToSign = bytes.concat(
            header,
            abi.encodePacked(outTokenAddress, outAmount),
            abi.encodePacked(inTokenAddress, inAmount)
        );

        bytes memory takerToSign = bytes.concat(
            header,
            abi.encodePacked(inTokenAddress, inAmount),
            abi.encodePacked(outTokenAddress, outAmount)
        );

        makerIntent = bytes.concat(bytes20(maker), bytes20(address(this)), bytes2(uint16(32)), bytes2(uint16(104)), bytes2(sLen), makerToSign);
        makerHash = keccak256(abi.encode(makerToSign, address(this), block.chainid));
        makerRelayerHash = keccak256(abi.encode(makerHash, relayer));

        takerIntent = bytes.concat(bytes20(taker), bytes20(address(this)), bytes2(uint16(32)), bytes2(uint16(104)), bytes2(sLen), takerToSign);
        takerHash = keccak256(abi.encode(takerToSign, address(this), block.chainid));
        takerRelayerHash = keccak256(abi.encode(takerHash, relayer));

        return (makerIntent, makerHash, makerRelayerHash, takerIntent, takerHash, takerRelayerHash);
    }

    function executeUserIntent(bytes calldata intent) external returns (bytes memory) {
        (address sender, ) = PackedIntent.getSenderAndStandard(intent);
        bytes memory executeCallData = abi.encodeWithSelector(IACCOUNT_EXECUTE_USER_INTENT_SELECTOR, intent);

        (, bytes memory result) = sender.call{value : 0, gas : gasleft()}(executeCallData);
        return result;
    }
}
