// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MessageHashUtils} from "openzeppelin/utils/cryptography/MessageHashUtils.sol";
import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";
import {IERC20} from "openzeppelin/token/ERC20/IERC20.sol";
import {UserIntent} from "./../interfaces/UserIntent.sol";
import {IStandard} from "./../interfaces/IStandard.sol";
import {IAccount} from "./../interfaces/IAccount.sol";

contract ICS1 is IStandard {
    using ECDSA for bytes32;

    string public constant ICS_NUMBER = "ICS1";
    string public constant NAME = "Direct Execution Standard with Expiration, Nonce and ERC20 Reward";
    string public constant VERSION = "0.0.0";
    string public constant AUTHOR = "hellohanchen";

    bytes4 public constant VALIDATION_APPROVED = 0x00000001;
    bytes4 public constant VALIDATION_DENIED = 0x00000000;
    uint256 public constant MAX_INSTRUCTIONS = 32;
    bytes4 public constant ERC20_TRANSFER_SELECTOR = IERC20.transfer.selector;
    bytes4 public constant IACCOUNT_EXECUTE_USER_INTENT_SELECTOR = IAccount.executeUserIntent.selector;

    mapping(address => mapping(uint256 => bool)) internal _nonces;

    function validateUserIntent(UserIntent calldata intent) external view returns (bytes4) {
        require(intent.instructions.length <= MAX_INSTRUCTIONS, "Too many instructions");

        (bool validated, uint256 nonce, uint256 timestamp, address tokenAddress, ) = this.decodeHeader(intent.header);
        require(validated, "Invalid header");
        require(timestamp >= block.timestamp, "Intent expired");
        require(!_nonces[intent.sender][nonce], "Nonce used");
        require(intent.signatures.length == 1, "Only 1 signature allowed");

        try IERC20(tokenAddress).totalSupply() {
            // no op
        } catch {
            revert("Not ERC20");
        }

        bytes32 intentHash = keccak256(abi.encode(intent.header, intent.standard, intent.instructions, block.chainid));
        bytes32 messageHash = MessageHashUtils.toEthSignedMessageHash(intentHash);
        require(intent.sender == messageHash.recover(intent.signatures[0]), "Invalid signature");

        return VALIDATION_APPROVED;
    }

    function unpackOperations(UserIntent calldata intent) external view returns (bytes memory, bytes[] memory) {
        (bool validated, uint256 nonce, , address tokenAddress, uint256 amount) = this.decodeHeader(intent.header);
        if (!validated) {
            return (abi.encodePacked(VALIDATION_DENIED), new bytes[](0));  // invalid header
        }

        bytes[] memory unpackedInstructions = new bytes[](intent.instructions.length + 2);

        for (uint256 i = 0; i < intent.instructions.length; i++) {
            unpackedInstructions[i] = intent.instructions[i];
        }

        address relayer = tx.origin;
        bytes memory transferCallData = abi.encodeWithSelector(ERC20_TRANSFER_SELECTOR, relayer, amount);
        bytes memory transferInstruction = abi.encode(tokenAddress, uint256(0), transferCallData);
        unpackedInstructions[intent.instructions.length] = transferInstruction;

        bytes memory nonceCallData = abi.encodeWithSelector(this.markNonce.selector, nonce);
        bytes memory nonceInstruction = abi.encode(address(this), 0, nonceCallData);
        unpackedInstructions[intent.instructions.length + 1] = nonceInstruction;

        return (abi.encodePacked(VALIDATION_APPROVED), unpackedInstructions);
    }

    function decodeHeader(bytes calldata header) external pure returns (bool, uint256, uint256, address, uint256) {
        if (header.length != 128) {
            return (false, 0, 0, address(0), 0);
        }

        (uint256 nonce, uint256 timestamp, address tokenAddress, uint256 amount) = abi.decode(header, (uint256, uint256, address, uint256));

        return (true, nonce, timestamp, tokenAddress, amount);
    }

    function markNonce(uint256 nonce) external {
        _nonces[msg.sender][nonce] = true;
    }

    function sampleHeader(uint256 nonce, address destination, address tokenAddress, uint256 amount, uint256 reward) external view returns (bytes memory, bytes[] memory, bytes32) {
        bytes memory transferCallData = abi.encodeWithSelector(ERC20_TRANSFER_SELECTOR, destination, amount);
        bytes memory transferInstruction = abi.encode(tokenAddress, uint256(0), transferCallData);
        bytes[] memory instructions = new bytes[](1);
        instructions[0] = transferInstruction;

        uint256 timestamp = block.timestamp + 31536000;
        bytes memory header = abi.encode(nonce, timestamp, tokenAddress, reward);
        bytes32 intentHash = keccak256(abi.encode(header, address(this), instructions, block.chainid));

        return (header, instructions, intentHash);
    }

    function executeUserIntent(UserIntent calldata intent) external returns (bytes memory) {
        bytes memory executeCallData = abi.encodeWithSelector(IACCOUNT_EXECUTE_USER_INTENT_SELECTOR, intent);

        (, bytes memory result) = intent.sender.call{value: 0, gas: gasleft()}(executeCallData);
        return result;
    }

    receive() external payable {}
}
