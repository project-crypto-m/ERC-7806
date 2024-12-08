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
    string public constant NAME = "Timed Nonced Pre-Delegated ERC20 Token Swap and Execution Standard";
    string public constant VERSION = "0.0.0";
    string public constant AUTHOR = "hellohanchen";

    bytes4 public constant VALIDATION_DENIED = 0x00000000;
    bytes4 public constant VALIDATION_APPROVED = 0x00000001;
    bytes4 public constant VALIDATION_APPROVED_SENDER_ONLY = 0x00000002;
    uint256 public constant MAX_INSTRUCTIONS = 128;
    bytes4 public constant ERC20_TRANSFER_SELECTOR = IERC20.transfer.selector;
    bytes4 public constant ISTANDARD_VALIDATE_USER_INTENT_SELECTOR = IStandard.validateUserIntent.selector;
    bytes4 public constant IACCOUNT_EXECUTE_USER_INTENT_SELECTOR = IAccount.executeUserIntent.selector;

    struct UnpackedHeader {
        bool validated;
        bytes header;
        bytes nestedHeader;
        uint256 nonce;
        uint256 timestamp;
        uint256 numOutTokens;
        uint256 numSignedIns;
        address solver;
    }

    mapping(bytes32 => bool) internal _nonces;

    function validateUserIntent(UserIntent calldata intent) external view returns (bytes4) {
        require(intent.instructions.length <= MAX_INSTRUCTIONS, "Too many instructions");
        require(intent.standard == address(this), "Not this standard");
        require(intent.signatures.length >= 1, "At least 1 signature is needed");

        UnpackedHeader memory unpackedHeader = this.unpackHeader(intent.header);
        require(unpackedHeader.validated, "Invalid header");
        require(unpackedHeader.timestamp >= block.timestamp, "Intent expired");
        require(!this.checkNonce(intent.sender, unpackedHeader.nonce), "Nonce used");
        require(intent.instructions.length >= unpackedHeader.numSignedIns, "Not enough instructions");

        bytes[] memory signedInstructions = new bytes[](unpackedHeader.numSignedIns);

        for (uint256 i = 0; i < unpackedHeader.numSignedIns; i++) {
            signedInstructions[i] = intent.instructions[i];

            // token instructions MUST be in (address, uint256) format
            if (intent.instructions[i].length != 64) {
                if (i < unpackedHeader.numOutTokens) {
                    revert("Invalid outToken instruction");
                }
            } else {
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
        }

        uint256 numUsedSig = 1;
        // validate sender's intent signature which includes solver
        bytes32 intentHash = keccak256(abi.encode(unpackedHeader.header, intent.standard, signedInstructions, block.chainid));
        bytes32 messageHash = MessageHashUtils.toEthSignedMessageHash(intentHash);
        require(intent.sender == messageHash.recover(intent.signatures[0]), "Invalid sender signature");

        // Case 1. Sender == solver, Self-solved, any one can be relayer
        if (intent.sender != unpackedHeader.solver) {
            if (unpackedHeader.solver == address(0)) {
                // Case 2. Not self-solved but solver is not determined, not need to check nestedIntent
                return VALIDATION_APPROVED_SENDER_ONLY;
            }

            // Case 3. Not self-solved and solver is determined
            // 1. solver signs with relayer == address(0) to bypass validation and everyone can validate this intent
            // 2. solver signs with relayer address that needs to be tx.origin
            require(intent.signatures.length >= 2, "At least 2 signatures are needed if solver is already determined");
            intentHash = keccak256(abi.encode(intentHash, address(0)));
            messageHash = MessageHashUtils.toEthSignedMessageHash(intentHash);
            if (unpackedHeader.solver != messageHash.recover(intent.signatures[1])) {
                intentHash = keccak256(abi.encode(intentHash, tx.origin));  // check relayer
                messageHash = MessageHashUtils.toEthSignedMessageHash(intentHash);
                require(unpackedHeader.solver == messageHash.recover(intent.signatures[1]), "Invalid solver signature");

                numUsedSig = 2;
            }
        }

        if (unpackedHeader.nestedHeader.length == 0) {
            // no more nested intent
            return VALIDATION_APPROVED;
        }

        // nested intent
        UserIntent memory nestedIntent = _buildNestedIntent(intent, unpackedHeader, numUsedSig);
        return IStandard(nestedIntent.standard).validateUserIntent(nestedIntent);
    }

    function unpackOperations(UserIntent calldata intent) external view returns (bytes memory, bytes[] memory) {
        require(intent.instructions.length <= MAX_INSTRUCTIONS, "Too many instructions");
        require(intent.standard == address(this), "Not this standard");
        require(intent.signatures.length >= 1, "At least 1 signature is needed");

        UnpackedHeader memory unpackedHeader = this.unpackHeader(intent.header);
        require(unpackedHeader.validated, "Invalid header");
        require(unpackedHeader.solver != address(0), "Invalid solver");  // to unpack the intent, the solver must be determined already
        require(unpackedHeader.timestamp >= block.timestamp, "Intent expired");
        require(!this.checkNonce(intent.sender, unpackedHeader.nonce), "Nonce used");
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

        uint256 numUsedSig = 1;
        // validate sender's intent signature which includes solver
        bytes32 intentHash = keccak256(abi.encode(unpackedHeader.header, intent.standard, signedInstructions, block.chainid));
        bytes32 messageHash = MessageHashUtils.toEthSignedMessageHash(intentHash);
        require(intent.sender == messageHash.recover(intent.signatures[0]), "Invalid sender signature");

        if (intent.sender != unpackedHeader.solver && unpackedHeader.solver != tx.origin) {
            // not self-solved and solver is not relayer
            require(intent.signatures.length >= 2, "At least 2 signatures are needed");
            intentHash = keccak256(abi.encode(intentHash, tx.origin));  // check relayer
            messageHash = MessageHashUtils.toEthSignedMessageHash(intentHash);
            require(unpackedHeader.solver == messageHash.recover(intent.signatures[1]), "Invalid solver signature");
            numUsedSig = 2;
        }

        // nested intent
        if (unpackedHeader.nestedHeader.length > 0) {
            UserIntent memory nestedIntent = _buildNestedIntent(intent, unpackedHeader, numUsedSig);
            bytes memory executeCallData = abi.encodeWithSelector(IACCOUNT_EXECUTE_USER_INTENT_SELECTOR, nestedIntent);
            bytes memory executeInstruction = abi.encode(nestedIntent.sender, uint256(0), executeCallData);
            unpackedInstructions[unpackedHeader.numOutTokens] = executeInstruction;
        }

        bytes memory nonceCallData = abi.encodeWithSelector(this.markNonce.selector, unpackedHeader.nonce);
        bytes memory nonceInstruction = abi.encode(address(this), 0, nonceCallData);
        unpackedInstructions[unpackedHeader.numSignedIns + hasNestedIntent] = nonceInstruction;

        return (abi.encode(VALIDATION_APPROVED), unpackedInstructions);
    }

    // helper function to unpack the
    function unpackHeader(bytes calldata header) external pure returns (UnpackedHeader memory) {
        (bytes memory senderHeader, bytes memory nestedHeader) = abi.decode(header, (bytes, bytes));

        if (senderHeader.length != 160) {
            return UnpackedHeader(false, new bytes(0), new bytes(0), 0, 0, 0, 0, address(0));
        }

        (uint256 nonce, uint256 timestamp, uint256 numOutTokens, uint256 numInstructions, address solver) = abi.decode(senderHeader, (uint256, uint256, uint256, uint256, address));

        return UnpackedHeader(true, senderHeader, nestedHeader, nonce, timestamp, numOutTokens, numOutTokens + numInstructions, solver);
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
        require(erc20Token.balanceOf(address(this)) >= amount, "Insufficient ERC20 balance");
        bool success = erc20Token.transfer(msg.sender, amount);
        require(success, "Failed to send ERC20");
    }

    // -------------
    // The following methods will be removed after testing
    // -------------
    function sampleIntent(
        uint256 nonce,
        address outTokenAddress,
        uint256 outAmount,
        address inTokenAddress,
        uint256 inAmount,
        bytes[] calldata instructions,
        address solver,
        address relayer
    ) external view returns (bytes memory, bytes[] memory, bytes32, bytes32) {
        bytes[] memory sampleInstructions = new bytes[](instructions.length + 2);
        sampleInstructions[0] = abi.encode(outTokenAddress, outAmount);
        sampleInstructions[1] = abi.encode(inTokenAddress, inAmount);

        for (uint256 i = 0; i < instructions.length; i++) {
            sampleInstructions[i + 2] = instructions[i];
        }

        uint256 timestamp = block.timestamp + 31536000;
        bytes memory header = abi.encode(nonce, timestamp, uint256(1), uint256(1), solver);
        bytes32 intentHash = keccak256(abi.encode(header, address(this), sampleInstructions, block.chainid));
        bytes32 solverHash = keccak256(abi.encode(intentHash, relayer));

        return (header, sampleInstructions, intentHash, solverHash);
    }

    function sampleNestedIntent(uint256 nonce, address relayer, address tokenAddress, uint256 amount) external view returns (bytes memory, bytes[] memory, bytes32) {
        bytes memory transferCallData = abi.encodeWithSelector(ERC20_TRANSFER_SELECTOR, address(this), amount);
        bytes memory transferInstruction = abi.encode(tokenAddress, uint256(0), transferCallData);
        bytes[] memory instructions = new bytes[](2);
        instructions[0] = abi.encode(relayer, address(this));
        instructions[1] = transferInstruction;

        bytes[] memory headerInstructions = new bytes[](1);
        headerInstructions[0] = transferInstruction;

        uint256 timestamp = block.timestamp + 31536000;
        bytes memory header = abi.encode(nonce, timestamp, 0, 1, relayer);  // fill in token address as reward placeholder
        bytes32 intentHash = keccak256(abi.encode(header, address(this), headerInstructions, block.chainid));

        return (abi.encode(header, new bytes(0)), instructions, intentHash);
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
