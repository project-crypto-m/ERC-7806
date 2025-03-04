// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MessageHashUtils} from "openzeppelin/utils/cryptography/MessageHashUtils.sol";
import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";
import {IERC20} from "openzeppelin/token/ERC20/IERC20.sol";
import {UserIntent} from "./../interfaces/UserIntent.sol";
import {IStandard} from "./../interfaces/IStandard.sol";
import {IAccount} from "./../interfaces/IAccount.sol";

contract ICS2 is IStandard {
    using ECDSA for bytes32;

    string public constant ICS_NUMBER = "ICS2";
    string public constant NAME = "Dynamic Multi ERC20 Token Swap Standard with Expiration, Nonce";
    string public constant VERSION = "0.0.0";
    string public constant AUTHOR = "hellohanchen";

    bytes4 public constant VALIDATION_APPROVED = 0x00000001;
    bytes4 public constant VALIDATION_DENIED = 0x00000000;
    uint256 public constant MAX_INSTRUCTIONS = 32;
    uint256 public constant MAX_TOKENS = 32;
    bytes4 public constant ERC20_TRANSFER_SELECTOR = IERC20.transfer.selector;
    bytes4 public constant ISTANDARD_VALIDATE_USER_INTENT_SELECTOR = IStandard.validateUserIntent.selector;
    bytes4 public constant IACCOUNT_EXECUTE_USER_INTENT_SELECTOR = IAccount.executeUserIntent.selector;

    struct UnpackedHeader {
        bool validated;
        uint256 nonce;
        uint256 timestamp;
        uint256 outTokens;
        uint256 totalTokens;
    }

    mapping(address => mapping(uint256 => bool)) internal _nonces;

    function validateUserIntent(UserIntent calldata intent) external view returns (bytes4) {
        require(intent.instructions.length <= MAX_INSTRUCTIONS, "Too many instructions");

        // Nested intent will have multi layers of headers
        (bytes memory header, bytes memory nestedHeader) = abi.decode(intent.header, (bytes, bytes));

        UnpackedHeader memory unpackedHeader = this.decodeHeader(header);
        require(unpackedHeader.validated, "Invalid ICS2 header");
        require(unpackedHeader.totalTokens <= MAX_TOKENS, "Too many tokens");
        require(unpackedHeader.timestamp >= block.timestamp, "Intent expired");
        require(!_nonces[intent.sender][unpackedHeader.nonce], "Nonce used");
        require(intent.instructions.length >= unpackedHeader.totalTokens + 1, "No enough instructions");
        require(intent.signatures.length >= 1, "At least 1 signature is needed");

        bytes[] memory tokenInstructions = new bytes[](unpackedHeader.totalTokens);

        for (uint256 i = 0; i < unpackedHeader.totalTokens; i++) {
            (address tokenAddress, ) = abi.decode(intent.instructions[i], (address, uint256));
            if (tokenAddress != address(0)) {
                // check if every token is ERC20
                try IERC20(tokenAddress).totalSupply() {
                    tokenInstructions[i] = intent.instructions[i];
                } catch {
                    revert("Not ERC20");
                }
            } else {
                tokenInstructions[i] = intent.instructions[i];
            }
        }

        // validate current intent signature
        bytes32 intentHash = keccak256(abi.encode(header, intent.standard, tokenInstructions, block.chainid));
        bytes32 messageHash = MessageHashUtils.toEthSignedMessageHash(intentHash);
        require(intent.sender == messageHash.recover(intent.signatures[0]), "Invalid signature");

        // nested intent
        UserIntent memory nestedIntent = _buildNestedIntent(nestedHeader, intent.instructions[unpackedHeader.totalTokens], intent.instructions, intent.signatures, unpackedHeader.totalTokens);
        return IStandard(nestedIntent.standard).validateUserIntent(nestedIntent);
    }

    function unpackOperations(UserIntent calldata intent) external view returns (bytes memory, bytes[] memory) {
        // Nested intent will have multi layers of headers
        (bytes memory header, bytes memory nestedHeader) = abi.decode(intent.header, (bytes, bytes));

        UnpackedHeader memory unpackedHeader = this.decodeHeader(header);
        if (!unpackedHeader.validated) {
            return (abi.encodePacked(VALIDATION_DENIED), new bytes[](0));  // invalid header
        }

        address relayer = tx.origin;
        bytes[] memory unpackedInstructions = new bytes[](unpackedHeader.totalTokens + 2);

        for (uint256 i = 0; i < unpackedHeader.outTokens; i++) {
            (address tokenAddress, uint256 amount) = abi.decode(intent.instructions[i], (address, uint256));

            // transfer tokens out to the relayer address
            if (tokenAddress == address(0)) {
                // native token
                bytes memory transferInstruction = abi.encode(relayer, amount, "");
                unpackedInstructions[i] = transferInstruction;
            } else {
                bytes memory transferCallData = abi.encodeWithSelector(ERC20_TRANSFER_SELECTOR, relayer, amount);
                bytes memory transferInstruction = abi.encode(tokenAddress, uint256(0), transferCallData);
                unpackedInstructions[i] = transferInstruction;
            }
        }

        // nested intent
        UserIntent memory nestedIntent = _buildNestedIntent(nestedHeader, intent.instructions[unpackedHeader.totalTokens], intent.instructions, intent.signatures, unpackedHeader.totalTokens);

        bytes memory executeCallData = abi.encodeWithSelector(IACCOUNT_EXECUTE_USER_INTENT_SELECTOR, nestedIntent);
        bytes memory executeInstruction = abi.encode(nestedIntent.sender, uint256(0), executeCallData);
        unpackedInstructions[unpackedHeader.outTokens] = executeInstruction;

        for (uint256 i = unpackedHeader.outTokens; i < unpackedHeader.totalTokens; i++) {
            (address tokenAddress, uint256 amount) = abi.decode(intent.instructions[i], (address, uint256));

            // transfer tokens out from this standard address
            if (tokenAddress == address(0)) {
                // native token
                bytes memory transferCallData = abi.encodeWithSelector(this.transferEth.selector, amount);
                bytes memory transferInstruction = abi.encode(address(this), uint256(0), transferCallData);
                unpackedInstructions[i + 1] = transferInstruction;
            } else {
                bytes memory transferCallData = abi.encodeWithSelector(this.transferERC20.selector, tokenAddress, amount);
                bytes memory transferInstruction = abi.encode(address(this), uint256(0), transferCallData);
                unpackedInstructions[i + 1] = transferInstruction;
            }
        }

        bytes memory nonceCallData = abi.encodeWithSelector(this.markNonce.selector, unpackedHeader.nonce);
        bytes memory nonceInstruction = abi.encode(address(this), 0, nonceCallData);
        unpackedInstructions[unpackedHeader.totalTokens + 1] = nonceInstruction;

        return (abi.encodePacked(VALIDATION_APPROVED), unpackedInstructions);
    }

    function _buildNestedIntent(bytes memory nestedHeader, bytes memory nestedIntentIns, bytes[] memory intentIns, bytes[] memory intentSigs, uint256 offset) internal pure returns (UserIntent memory nestedIntent) {
        (address nestedSender, address nestedStandard) = abi.decode(nestedIntentIns, (address, address));
        uint256 numNestedIns = intentIns.length - offset - 1;
        bytes[] memory nestedInstructions = new bytes[](numNestedIns);
        for (uint256 i = 0; i < numNestedIns; i++) {
            nestedInstructions[i] = intentIns[offset + 1 + i];
        }
        bytes[] memory nestedSignatures = new bytes[](intentSigs.length - 1);
        for (uint256 i = 0; i < intentSigs.length - 1; i++) {
            nestedSignatures[i] = intentSigs[i + 1];
        }
        nestedIntent.sender = nestedSender;
        nestedIntent.standard = nestedStandard;
        nestedIntent.header = nestedHeader;
        nestedIntent.instructions = nestedInstructions;
        nestedIntent.signatures = nestedSignatures;

        return nestedIntent;
    }

    function decodeHeader(bytes calldata header) external pure returns (UnpackedHeader memory) {
        if (header.length != 128) {
            return UnpackedHeader(false, 0, 0, 0, 0);
        }

        (uint256 nonce, uint256 timestamp, uint256 outTokens, uint256 inTokens) = abi.decode(header, (uint256, uint256, uint256, uint256));

        return UnpackedHeader(true, nonce, timestamp, outTokens, outTokens + inTokens);
    }

    function markNonce(uint256 nonce) external {
        _nonces[msg.sender][nonce] = true;

        emit NonceUsed(msg.sender, nonce);
    }

    function transferEth(uint256 amount) external {
        require(address(this).balance >= amount, "Insufficient balance");
        bool success = payable(msg.sender).send(amount);  // send to the caller
        require(success, "Failed to send Ether");
    }

    function transferERC20(address token, uint256 amount) external {
        IERC20 erc20Token = IERC20(token);
        require(erc20Token.balanceOf(address(this)) >= amount, "Insufficient ERC20 balance");
        bool success = erc20Token.transfer(msg.sender, amount);
        require(success, "Failed to send ERC20");
    }

    function sampleIntent(uint256 nonce, address outTokenAddress, uint256 outAmount, address inTokenAddress, uint256 inAmount) external view returns (bytes memory, bytes[] memory, bytes32) {
        bytes memory outTokenIns = abi.encode(outTokenAddress, outAmount);
        bytes memory inTokenIns = abi.encode(inTokenAddress, inAmount);
        bytes[] memory instructions = new bytes[](2);
        instructions[0] = outTokenIns;
        instructions[1] = inTokenIns;

        uint256 timestamp = block.timestamp + 31536000;
        bytes memory header = abi.encode(nonce, timestamp, uint256(1), uint256(1));
        bytes32 intentHash = keccak256(abi.encode(header, address(this), instructions, block.chainid));

        return (header, instructions, intentHash);
    }

    function sampleNestedIntent(uint256 nonce, address relayer, address standard, address tokenAddress, uint256 amount) external view returns (bytes memory, bytes[] memory, bytes32) {
        bytes memory transferCallData = abi.encodeWithSelector(ERC20_TRANSFER_SELECTOR, address(this), amount);
        bytes memory transferInstruction = abi.encode(tokenAddress, uint256(0), transferCallData);
        bytes[] memory instructions = new bytes[](2);
        instructions[0] = abi.encode(relayer, standard);
        instructions[1] = transferInstruction;

        bytes[] memory headerInstructions = new bytes[](1);
        headerInstructions[0] = transferInstruction;

        uint256 timestamp = block.timestamp + 31536000;
        bytes memory header = abi.encode(nonce, timestamp, tokenAddress, 0);  // fill in token address as reward placeholder
        bytes32 intentHash = keccak256(abi.encode(header, standard, headerInstructions, tokenAddress, 0, block.chainid));

        return (header, instructions, intentHash);
    }

    function getNestedIntentHeader(bytes calldata header, bytes calldata nestedHeader) external pure returns (bytes memory) {
        return abi.encode(header, nestedHeader);
    }

    function executeUserIntent(UserIntent calldata intent) external returns (bytes memory) {
        bytes memory executeCallData = abi.encodeWithSelector(IACCOUNT_EXECUTE_USER_INTENT_SELECTOR, intent);

        (, bytes memory result) = intent.sender.call{value: 0, gas: gasleft()}(executeCallData);
        return result;
    }

    receive() external payable {}
}
