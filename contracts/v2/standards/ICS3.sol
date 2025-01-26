// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MessageHashUtils} from "openzeppelin/utils/cryptography/MessageHashUtils.sol";
import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";
import {IERC20} from "openzeppelin/token/ERC20/IERC20.sol";
import {UserIntent} from "./../interfaces/UserIntent.sol";
import {IStandard} from "./../interfaces/IStandard.sol";
import {ITokenRelayer} from "./../interfaces/ITokenRelayer.sol";
import {IAccount} from "./../interfaces/IAccount.sol";

contract ICS3 is IStandard, ITokenRelayer {
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

    mapping(bytes32 => bool) internal _hashes;

    struct UnpackedHeader {
        bytes32 header;
        uint64 timestamp;
        address solver;
    }

    // helper function to unpack the
    function unpackHeader(bytes calldata headers) external pure returns (UnpackedHeader memory) {
        require(headers.length >= 32, "Header too short");

        // nonce = uint32(bytes4(header[:4]));  // we don't need to parse nonce
        uint64 timestamp = uint64(bytes8(headers[4 : 12]));
        address solver = address(bytes20(headers[12 : 32]));

        return UnpackedHeader(bytes32(headers[: 32]), timestamp, solver);
    }

    function validateUserIntent(UserIntent calldata intent) external view returns (bytes4) {
        require(intent.standard == address(this), "Not this standard");
        require(intent.signatures.length >= 65, "At least 1 signature is needed");

        UnpackedHeader memory unpackedHeader = this.unpackHeader(intent.headers);
        require(unpackedHeader.timestamp >= block.timestamp, "Intent expired");

        // validate out token instruction
        address tokenAddress = address(bytes20(intent.instructions[: 20]));
        uint256 amount = uint256(bytes32(intent.instructions[20 : 52]));
        if (tokenAddress != address(0)) {
            try IERC20(tokenAddress).balanceOf(intent.sender) returns (uint256 balance) {
                require(balance >= amount, "Insufficient token balance");
            } catch {
                revert("Not ERC20 token");
            }
        } else {
            require(intent.sender.balance >= amount, "Insufficient eth balance");
        }

        tokenAddress = address(bytes20(intent.instructions[52 : 72]));
        amount = uint256(bytes32(intent.instructions[72 : 104]));
        if (tokenAddress != address(0)) {
            // check if in token is ERC20
            try IERC20(tokenAddress).totalSupply() {
                // no op
            } catch {
                revert("Not ERC20 token");
            }
        }

        (uint256 numUsedSig, uint256 hash) = _validateSignatures(intent.sender, unpackedHeader, intent.instructions, intent.signatures);
        require(!this.checkHash(intent.sender, hash), "Hash executed");
        if (numUsedSig == 0) {
            return VALIDATION_APPROVED_SENDER_ONLY;
        }

        if (intent.headers.length == 32) {
            return VALIDATION_APPROVED;
        }

        // nested intent
        UserIntent memory nestedIntent = _buildNestedIntent(intent, numUsedSig);
        return IStandard(nestedIntent.standard).validateUserIntent(nestedIntent);
    }

    function unpackOperations(UserIntent calldata intent) external view returns (bytes4, bytes[] memory) {
        require(intent.standard == address(this), "Not this standard");
        require(intent.signatures.length >= 65, "At least 1 signature is needed");

        UnpackedHeader memory unpackedHeader = this.unpackHeader(intent.headers);
        require(unpackedHeader.solver != address(0), "Invalid solver");
        // to unpack the intent, the solver must be determined already
        require(unpackedHeader.timestamp >= block.timestamp, "Intent expired");

        uint256 hasNestedIntent = intent.headers.length == 32 ? 0 : 1;

        // total instructions = signed + nestIntent execution (optional) + mark nonce
        bytes[] memory unpackedInstructions = new bytes[](2 + hasNestedIntent + 1);

        // out token instruction
        address tokenAddress = address(bytes20(intent.instructions[: 20]));
        uint256 amount = uint256(bytes32(intent.instructions[20 : 52]));
        if (tokenAddress == address(0)) {
            unpackedInstructions[0] = abi.encode(address(this), amount, "");
        } else {
            // check if every token is ERC20
            try IERC20(tokenAddress).totalSupply() {
                unpackedInstructions[0] = abi.encode(
                    tokenAddress,
                    uint256(0),
                    abi.encodeWithSelector(ERC20_TRANSFER_SELECTOR, address(this), amount));
            } catch {
                revert("Not ERC20 token");
            }
        }

        tokenAddress = address(bytes20(intent.instructions[52 : 72]));
        amount = uint256(bytes32(intent.instructions[72 : 104]));
        // transfer tokens out from this standard address
        if (tokenAddress == address(0)) {
            // native token
            unpackedInstructions[1 + hasNestedIntent] = abi.encode(
                address(this), uint256(0), abi.encodeWithSelector(this.transferEth.selector, amount));
        } else {
            // check if every token is ERC20
            try IERC20(tokenAddress).totalSupply() {
                unpackedInstructions[1 + hasNestedIntent] = abi.encode(
                    address(this), uint256(0), abi.encodeWithSelector(this.transferERC20.selector, tokenAddress, amount));
            } catch {
                revert("Not ERC20 token");
            }
        }

        // because solver != address(0), this numUsedSig can only be 1 or 2
        (uint256 numUsedSig, uint256 hash) = _validateSignatures(intent.sender, unpackedHeader, intent.instructions, intent.signatures);
        require(!this.checkHash(intent.sender, hash), "Nonce used");

        // nested intent
        if (intent.headers.length > 32) {
            UserIntent memory nestedIntent = _buildNestedIntent(intent, numUsedSig);
            unpackedInstructions[1] = abi.encode(
                nestedIntent.sender,
                uint256(0),
                abi.encodeWithSelector(IACCOUNT_EXECUTE_USER_INTENT_SELECTOR, nestedIntent));
        }

        unpackedInstructions[2 + hasNestedIntent] = abi.encode(
            address(this), 0, abi.encodeWithSelector(this.markHash.selector, hash));

        return (VALIDATION_APPROVED, unpackedInstructions);
    }

    function _validateSignatures(
        address sender,
        UnpackedHeader memory unpackedHeader,
        bytes calldata instructions,
        bytes calldata signatures
    ) internal view returns (uint256, uint256) {
        bytes32 intentHash = keccak256(abi.encode(unpackedHeader.header, address(this), instructions[: 104], block.chainid));
        bytes32 messageHash = MessageHashUtils.toEthSignedMessageHash(intentHash);
        require(sender == messageHash.recover(signatures[: 65]), "Invalid sender signature");

        if (unpackedHeader.solver == address(0)) {
            return (0, uint256(intentHash));
            // solver is not determined, no need to check nested intent
        }

        if (unpackedHeader.solver == sender || unpackedHeader.solver == tx.origin) {
            // only 1 signature is used if
            // 1. self-solved
            // 2. solver-relayed
            return (1, uint256(intentHash));
        }

        require(signatures.length >= 130, "At least 2 signatures are needed to assign relayer");
        bytes32 solverHash = keccak256(abi.encode(intentHash, tx.origin));
        messageHash = MessageHashUtils.toEthSignedMessageHash(solverHash);
        if (unpackedHeader.solver == messageHash.recover(signatures[65 : 130])) {
            return (2, uint256(intentHash));
        }

        // 1. solver signs with relayer == address(0) to bypass validation and everyone can relay this intent
        solverHash = keccak256(abi.encode(intentHash, address(0)));
        messageHash = MessageHashUtils.toEthSignedMessageHash(solverHash);
        require(unpackedHeader.solver == messageHash.recover(signatures[65 : 130]), "Invalid solver signature");

        return (2, uint256(intentHash));
    }

    function _buildNestedIntent(UserIntent calldata intent, uint256 numUsedSig) internal pure returns (UserIntent memory nestedIntent) {
        require(intent.headers.length > 32, "No nested intent");

        nestedIntent.sender = address(bytes20(intent.instructions[104 : 124]));
        nestedIntent.standard = address(bytes20(intent.instructions[124 : 144]));
        nestedIntent.headers = intent.headers[32 :];
        nestedIntent.instructions = intent.instructions[144 :];
        nestedIntent.signatures = intent.signatures[numUsedSig * 65 :];

        return nestedIntent;
    }

    function checkHash(address sender, uint256 hash) external view returns (bool) {
        bytes32 compositeKey = keccak256(abi.encode(sender, hash));
        return _hashes[compositeKey];
    }

    function markHash(uint256 hash) external {
        bytes32 compositeKey = keccak256(abi.encode(msg.sender, hash));
        _hashes[compositeKey] = true;

        emit NonceUsed(msg.sender, hash);
    }

    // allow accounts to use standard as a relayer of assets
    function transferEth(uint256 amount) external {
        require(address(this).balance >= amount, "Insufficient balance");
        bool success = payable(msg.sender).send(amount);
        // send to the caller
        require(success, "Failed to send Ether");
    }

    // allow accounts to use standard as a relayer of assets
    function transferERC20(address token, uint256 amount) external {
        bool success = IERC20(token).transfer(msg.sender, amount);
        require(success, "Failed to send ERC20");
    }

    // -------------
    // The following methods will be removed after testing
    // -------------
    function sampleIntent(
        uint32 nonce,
        address outTokenAddress,
        uint256 outAmount,
        address inTokenAddress,
        uint256 inAmount,
        address solver,
        address relayer
    ) external view returns (bytes32, bytes memory, bytes memory, bytes32, bytes32, bytes memory, bytes32, bytes32) {
        bytes memory makerInstructions = bytes.concat(
            abi.encodePacked(outTokenAddress, outAmount),
            abi.encodePacked(inTokenAddress, inAmount)
        );

        bytes memory takerInstructions = bytes.concat(
            abi.encodePacked(inTokenAddress, inAmount),
            abi.encodePacked(outTokenAddress, outAmount)
        );

        bytes32 header = bytes32(abi.encodePacked(nonce, uint64((block.timestamp + 31536000) & 0xFFFFFFFFFFFFFFFF), solver));
        bytes32 makerIntentHash = keccak256(abi.encode(header, address(this), makerInstructions, block.chainid));
        bytes32 takerIntentHash = keccak256(abi.encode(header, address(this), takerInstructions, block.chainid));

        return (header, abi.encodePacked(header, header),
        makerInstructions, makerIntentHash, keccak256(abi.encode(makerIntentHash, relayer)),
        takerInstructions, takerIntentHash, keccak256(abi.encode(takerIntentHash, relayer)));
    }

    function executeUserIntent(UserIntent calldata intent) external returns (bytes memory) {
        bytes memory executeCallData = abi.encodeWithSelector(IACCOUNT_EXECUTE_USER_INTENT_SELECTOR, intent);

        (, bytes memory result) = intent.sender.call{value : 0, gas : gasleft()}(executeCallData);
        return result;
    }

    receive() external payable {}
}
