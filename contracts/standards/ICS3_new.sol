// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MessageHashUtils} from "openzeppelin/utils/cryptography/MessageHashUtils.sol";
import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";
import {IERC20} from "openzeppelin/token/ERC20/IERC20.sol";
import {UserIntent} from "./../interfaces/UserIntent.sol";
import {IStandard} from "./../interfaces/IStandard.sol";
import {IAccount} from "./../interfaces/IAccount.sol";

contract ICS3 is IStandard {
    using ECDSA for bytes32;

    string public constant ICS_NUMBER = "ICS3";
    string public constant DESCRIPTION = "Timed Hashed Pre-Delegated ERC20 Token Swap and Execution Standard";
    string public constant VERSION = "0.0.0";
    string public constant AUTHOR = "hellohanchen";

    bytes4 public constant VALIDATION_DENIED = 0x00000000;
    bytes4 public constant VALIDATION_APPROVED = 0x00000001;
    bytes4 public constant VALIDATION_APPROVED_SENDER_ONLY = 0x00000002;
    uint256 public constant MAX_INSTRUCTIONS = 128;
    bytes4 public constant ERC20_TRANSFER_SELECTOR = IERC20.transfer.selector;
    bytes4 public constant ISTANDARD_VALIDATE_USER_INTENT_SELECTOR = IStandard.validateUserIntent.selector;
    bytes4 public constant IACCOUNT_EXECUTE_USER_INTENT_SELECTOR = IAccount.executeUserIntent.selector;

    mapping(bytes32 => bool) internal _nonces;

    struct UnpackedHeader {
        bytes32 header;
        bytes nestedHeader;
        uint64 timestamp;
        uint16 numOutTokens;
        uint16 numSignedIns;
        address solver;
    }

    // helper function to unpack the
    function unpackHeader(bytes calldata header) external pure returns (UnpackedHeader memory) {
        require(header.length >= 32, "Invalid ICS3 singleton header");

        uint64 timestamp = uint64(bytes8(header[:8]));
        uint16 numOutTokens = uint16(bytes2(header[8:10]));
        uint16 numInstructions = uint16(bytes2(header[10:12]));
        address solver = address(bytes20(header[12:32]));

        return UnpackedHeader(bytes32(header[:32]), header[32:], timestamp, numOutTokens, numOutTokens + numInstructions, solver);
    }

    function validateUserIntent(UserIntent calldata intent) external view returns (bytes4) {
        require(intent.standard == address(this), "Not this standard");
        require(intent.instructions.length <= MAX_INSTRUCTIONS, "Too many instructions");
        require(intent.signatures.length >= 1, "At least 1 signature is needed");

        UnpackedHeader memory unpackedHeader = this.unpackHeader(intent.header);
        require(unpackedHeader.timestamp >= block.timestamp, "Intent expired");
        require(intent.instructions.length >= unpackedHeader.numSignedIns, "Not enough instructions");

        bytes[] memory signedInstructions = new bytes[](unpackedHeader.numSignedIns);

        // validate out token instructions
        for (uint256 i = 0; i < unpackedHeader.numOutTokens; i++) {
            require(intent.instructions[i].length == 64, "Invalid outToken instruction");

            // ONLY token instructions CAN have (address, uint256) format
            (address tokenAddress, uint256 amount) = abi.decode(intent.instructions[i], (address, uint256));
            if (tokenAddress != address(0)) {
                try IERC20(tokenAddress).balanceOf(address(this)) returns (uint256 balance) {
                    require(balance >= amount, "Insufficient token balance");
                } catch {
                    revert("Not ERC20 token");
                }
            } else {
                require(address(this).balance >= amount, "Insufficient eth balance");
            }

            signedInstructions[i] = intent.instructions[i];
        }

        for (uint256 i = unpackedHeader.numOutTokens; i < unpackedHeader.numSignedIns; i++) {
            if (intent.instructions[i].length == 64) {
                // ONLY token instructions CAN have (address, uint256) format
                (address tokenAddress, ) = abi.decode(intent.instructions[i], (address, uint256));
                if (tokenAddress != address(0)) {
                    // check if every token is ERC20
                    try IERC20(tokenAddress).totalSupply() {
                        // no op
                    } catch {
                        revert("Not ERC20 token");
                    }
                }
            }

            signedInstructions[i] = intent.instructions[i];
        }

        (uint256 numUsedSig, uint256 nonce) = _validateSignatures(intent.sender, unpackedHeader, intent.instructions, intent.signatures);
        require(!this.checkNonce(intent.sender, nonce), "Nonce used");
        if (numUsedSig == 0) {
            return VALIDATION_APPROVED_SENDER_ONLY;
        }

        // nested intent
        UserIntent memory nestedIntent = _buildNestedIntent(intent, unpackedHeader, numUsedSig);
        return IStandard(nestedIntent.standard).validateUserIntent(nestedIntent);
    }

    function unpackOperations(UserIntent calldata intent) external view returns (bytes memory, bytes[] memory) {
        require(intent.standard == address(this), "Not this standard");
        require(intent.instructions.length <= MAX_INSTRUCTIONS, "Too many instructions");
        require(intent.signatures.length >= 1, "At least 1 signature is needed");

        UnpackedHeader memory unpackedHeader = this.unpackHeader(intent.header);
        require(unpackedHeader.solver != address(0), "Invalid solver");  // to unpack the intent, the solver must be determined already
        require(unpackedHeader.timestamp >= block.timestamp, "Intent expired");
        require(intent.instructions.length >= unpackedHeader.numSignedIns, "Not enough instructions");

        uint256 hasNestedIntent = 1;
        if (unpackedHeader.nestedHeader.length == 0) {
            hasNestedIntent = 0;
        }

        bytes[] memory signedInstructions = new bytes[](unpackedHeader.numSignedIns);
        // total instructions = signed + nestIntent execution (optional) + mark nonce
        bytes[] memory unpackedInstructions = new bytes[](unpackedHeader.numSignedIns + hasNestedIntent + 1);

        for (uint256 i = 0; i < unpackedHeader.numOutTokens; i++) {
            require(intent.instructions[i].length == 64, "Invalid token instruction");
            signedInstructions[i] = intent.instructions[i];

            (address tokenAddress, uint256 amount) = abi.decode(intent.instructions[i], (address, uint256));

            // transfer tokens out to the standard address
            if (tokenAddress == address(0)) {
                // native token
                bytes memory transferInstruction = abi.encode(address(this), amount, "");
                unpackedInstructions[i] = transferInstruction;
            } else {
                // check if every token is ERC20
                try IERC20(tokenAddress).totalSupply() {
                    bytes memory transferCallData = abi.encodeWithSelector(ERC20_TRANSFER_SELECTOR, address(this), amount);
                    bytes memory transferInstruction = abi.encode(tokenAddress, uint256(0), transferCallData);
                    unpackedInstructions[i] = transferInstruction;
                } catch {
                    revert("Not ERC20 token");
                }
            }
        }

        for (uint256 i = unpackedHeader.numOutTokens; i < unpackedHeader.numSignedIns; i++) {
            signedInstructions[i] = intent.instructions[i];

            if (intent.instructions[i].length != 64) {
                unpackedInstructions[i + hasNestedIntent] = intent.instructions[i];
            } else {
                (address tokenAddress, uint256 amount) = abi.decode(intent.instructions[i], (address, uint256));

                // transfer tokens out from this standard address
                if (tokenAddress == address(0)) {
                    // native token
                    bytes memory transferCallData = abi.encodeWithSelector(this.transferEth.selector, amount);
                    bytes memory transferInstruction = abi.encode(address(this), uint256(0), transferCallData);
                    unpackedInstructions[i + hasNestedIntent] = transferInstruction;
                } else {
                    // check if every token is ERC20
                    try IERC20(tokenAddress).totalSupply() {
                        bytes memory transferCallData = abi.encodeWithSelector(this.transferERC20.selector, tokenAddress, amount);
                        bytes memory transferInstruction = abi.encode(address(this), uint256(0), transferCallData);
                        unpackedInstructions[i + hasNestedIntent] = transferInstruction;
                    } catch {
                        revert("Not ERC20 token");
                    }
                }
            }
        }

        // because solver != address(0), this numUsedSig can only be 1 or 2
        (uint256 numUsedSig, uint256 nonce) = _validateSignatures(intent.sender, unpackedHeader, signedInstructions, intent.signatures);
        require(!this.checkNonce(intent.sender, nonce), "Nonce used");

        // nested intent
        if (unpackedHeader.nestedHeader.length > 0) {
            UserIntent memory nestedIntent = _buildNestedIntent(intent, unpackedHeader, numUsedSig);
            bytes memory executeCallData = abi.encodeWithSelector(IACCOUNT_EXECUTE_USER_INTENT_SELECTOR, nestedIntent);
            bytes memory executeInstruction = abi.encode(nestedIntent.sender, uint256(0), executeCallData);
            unpackedInstructions[unpackedHeader.numOutTokens] = executeInstruction;
        }

        bytes memory nonceCallData = abi.encodeWithSelector(this.markNonce.selector, nonce);
        bytes memory nonceInstruction = abi.encode(address(this), 0, nonceCallData);
        unpackedInstructions[unpackedHeader.numSignedIns + hasNestedIntent] = nonceInstruction;

        return (abi.encode(VALIDATION_APPROVED), unpackedInstructions);
    }

    function _validateSignatures(
        address sender,
        UnpackedHeader memory unpackedHeader,
        bytes[] memory signedInstructions,
        bytes[] memory signatures
    ) internal view returns (uint256, uint256) {
        bytes32 intentHash = keccak256(abi.encode(unpackedHeader.header, address(this), signedInstructions, block.chainid));
        bytes32 messageHash = MessageHashUtils.toEthSignedMessageHash(intentHash);
        require(sender == messageHash.recover(signatures[0]), "Invalid sender signature");

        if (unpackedHeader.solver == address(0)) {
            return (0, uint256(intentHash));  // solver is not determined, no need to check nested intent
        }

        if (unpackedHeader.solver == sender || unpackedHeader.solver == tx.origin) {
            // only 1 signature is used if
            // 1. self-solved
            // 2. solver-relayed
            return (1, uint256(intentHash));
        }

        require(signatures.length >= 2, "At least 2 signatures are needed to assign relayer");
        bytes32 solverHash = keccak256(abi.encode(intentHash, tx.origin));
        messageHash = MessageHashUtils.toEthSignedMessageHash(solverHash);
        if (unpackedHeader.solver == messageHash.recover(signatures[1])) {
            return (2, uint256(intentHash));
        }

        // 1. solver signs with relayer == address(0) to bypass validation and everyone can relay this intent
        solverHash = keccak256(abi.encode(intentHash, address(0)));
        messageHash = MessageHashUtils.toEthSignedMessageHash(solverHash);
        require(unpackedHeader.solver == messageHash.recover(signatures[1]), "Invalid solver signature");

        return (2, uint256(intentHash));
    }

    function _buildNestedIntent(UserIntent calldata intent, UnpackedHeader memory unpackedHeader, uint256 numUsedSig) internal pure returns (UserIntent memory nestedIntent) {
        require(unpackedHeader.nestedHeader.length > 0, "No nested intent");

        // the first instruction after the original sender instruction is the (nestedSender, nestedStandard) pair
        (address nestedSender, address nestedStandard) = abi.decode(intent.instructions[unpackedHeader.numSignedIns], (address, address));

        // all other instructions belong to nested intent
        uint256 numNestedIns = intent.instructions.length - unpackedHeader.numSignedIns - 1;
        bytes[] memory nestedInstructions = new bytes[](numNestedIns);
        for (uint256 i = 0; i < numNestedIns; i++) {
            nestedInstructions[i] = intent.instructions[unpackedHeader.numSignedIns + 1 + i];
        }

        bytes[] memory nestedSignatures = new bytes[](intent.signatures.length - numUsedSig);
        for (uint256 i = 0; i < intent.signatures.length - numUsedSig; i++) {
            nestedSignatures[i] = intent.signatures[i + numUsedSig];
        }
        nestedIntent.sender = nestedSender;
        nestedIntent.standard = nestedStandard;
        nestedIntent.header = unpackedHeader.nestedHeader;
        nestedIntent.instructions = nestedInstructions;
        nestedIntent.signatures = nestedSignatures;

        return nestedIntent;
    }

    function checkNonce(address sender, uint256 nonce) external view returns (bool) {
        bytes32 compositeKey = keccak256(abi.encode(sender, nonce));
        return _nonces[compositeKey];
    }

    function markNonce(uint256 nonce) external {
        bytes32 compositeKey = keccak256(abi.encode(msg.sender, nonce));
        _nonces[compositeKey] = true;

        emit NonceUsed(msg.sender, nonce);
    }

    // allow accounts to use standard as a relayer of assets
    function transferEth(uint256 amount) external {
        require(address(this).balance >= amount, "Insufficient balance");
        bool success = payable(msg.sender).send(amount);  // send to the caller
        require(success, "Failed to send Ether");
    }

    // allow accounts to use standard as a relayer of assets
    function transferERC20(address token, uint256 amount) external {
        IERC20 erc20Token = IERC20(token);
        bool success = erc20Token.transfer(msg.sender, amount);
        require(success, "Failed to send ERC20");
    }

    // -------------
    // The following methods will be removed after testing
    // -------------
    function sampleIntent(
        address outTokenAddress,
        uint256 outAmount,
        address inTokenAddress,
        uint256 inAmount,
        address solver,
        address relayer
    ) external view returns (bytes32, bytes memory, bytes[] memory, bytes32, bytes32, bytes[] memory, bytes32, bytes32) {
        bytes[] memory makerInstructions = new bytes[](2);
        makerInstructions[0] = abi.encode(outTokenAddress, outAmount);
        makerInstructions[1] = abi.encode(inTokenAddress, inAmount);

        bytes[] memory takerInstructions = new bytes[](2);
        takerInstructions[0] = makerInstructions[1];
        takerInstructions[1] = makerInstructions[0];

        bytes32 header = bytes32(abi.encodePacked(uint64((block.timestamp + 31536000) & 0xFFFFFFFFFFFFFFFF), uint16(1), uint16(1), solver));
        bytes32 makerIntentHash = keccak256(abi.encode(header, address(this), makerInstructions, block.chainid));
        bytes32 takerIntentHash = keccak256(abi.encode(header, address(this), takerInstructions, block.chainid));

        return (header, abi.encodePacked(header, header),
        makerInstructions, makerIntentHash, keccak256(abi.encode(makerIntentHash, relayer)),
        takerInstructions, takerIntentHash, keccak256(abi.encode(takerIntentHash, relayer)));
    }

    function executeUserIntent(UserIntent calldata intent) external returns (bytes memory) {
        bytes memory executeCallData = abi.encodeWithSelector(IACCOUNT_EXECUTE_USER_INTENT_SELECTOR, intent);

        (, bytes memory result) = intent.sender.call{value: 0, gas: gasleft()}(executeCallData);
        return result;
    }

    receive() external payable {}
}
