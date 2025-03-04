// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MessageHashUtils} from "openzeppelin/utils/cryptography/MessageHashUtils.sol";
import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";
import {IERC20} from "openzeppelin/token/ERC20/IERC20.sol";
import {Clones} from "openzeppelin/proxy/Clones.sol";
import {UserIntent} from "./../interfaces/UserIntent.sol";
import {StandardRegistry} from "./../StandardRegistry.sol";
import {IStandard} from "./../interfaces/IStandard.sol";
import {IAccount} from "./../interfaces/IAccount.sol";
import {InitializableRegistryBatchExecuteAccount} from "./../accounts/InitializableRegistryBatchExecuteAccount.sol";

contract ICS5 is IStandard {
    using ECDSA for bytes32;

    InitializableRegistryBatchExecuteAccount public constant IMPLEMENTATION =
    InitializableRegistryBatchExecuteAccount(payable(0x1EcBE25525F6e6cDe8631e602Df6D55D3967cDF8));

    string public constant ICS_NUMBER = "ICS5";
    string public constant NAME = "Owner Direct Execution Standard with Expiration, Nonce and ERC20 Reward";
    string public constant VERSION = "0.0.0";
    string public constant AUTHOR = "hellohanchen";

    bytes4 public constant VALIDATION_APPROVED = 0x00000001;
    bytes4 public constant VALIDATION_DENIED = 0x00000000;
    uint256 public constant MAX_INSTRUCTIONS = 32;
    bytes4 public constant ERC20_TRANSFER_SELECTOR = IERC20.transfer.selector;
    bytes4 public constant IACCOUNT_EXECUTE_USER_INTENT_SELECTOR = IAccount.executeUserIntent.selector;
    bytes4 public constant STANDARD_REGISTRY_UPDATE_SELECTOR = StandardRegistry.update.selector;

    mapping(address => mapping(uint256 => bool)) internal _nonces;
    mapping(address => address) internal _owners;

    function createAccount(address owner, bytes32 salt, bytes memory signature) external returns (address) {
        bytes32 saltHash = keccak256(abi.encode(salt, address(this), block.chainid));
        bytes32 messageHash = MessageHashUtils.toEthSignedMessageHash(saltHash);
        require(owner == messageHash.recover(signature), "Invalid signature");

        address impl = address(IMPLEMENTATION);
        bytes32 ownerSalt = keccak256(abi.encode(owner, salt));
        address account = Clones.predictDeterministicAddress(impl, ownerSalt);
        require(account.code.length == 0, "Contract already exists");

        address payable newAccount = payable(Clones.cloneDeterministic(impl, ownerSalt));

        bytes[] memory initInstructions = new bytes[](1);
        bytes memory updateCallData = abi.encodeWithSelector(STANDARD_REGISTRY_UPDATE_SELECTOR, true, address(this), 0);
        bytes memory updateInstruction = abi.encode(address(IMPLEMENTATION.REGISTRY()), uint256(0), updateCallData);
        initInstructions[0] = updateInstruction;

        InitializableRegistryBatchExecuteAccount newImpl = InitializableRegistryBatchExecuteAccount(newAccount);
        newImpl.initialize(initInstructions);

        _owners[account] = owner;

        return account;
    }

    function sampleSaltHash(bytes32 salt) external view returns (bytes32) {
        return keccak256(abi.encode(salt, address(this), block.chainid));
    }

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
        require(_owners[intent.sender] == messageHash.recover(intent.signatures[0]), "Invalid signature");

        return VALIDATION_APPROVED;
    }

    function unpackOperations(UserIntent calldata intent) external view returns (bytes memory, bytes[] memory) {
        (bool validated, uint256 nonce, uint256 timestamp, address tokenAddress, uint256 amount) = this.decodeHeader(intent.header);
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
        require(_owners[intent.sender] == messageHash.recover(intent.signatures[0]), "Invalid signature");

        bytes[] memory unpackedInstructions = new bytes[](intent.instructions.length + 2);

        for (uint256 i = 0; i < intent.instructions.length; i++) {
            unpackedInstructions[i] = intent.instructions[i];
        }

        bytes memory transferCallData = abi.encodeWithSelector(ERC20_TRANSFER_SELECTOR, tx.origin, amount);
        unpackedInstructions[intent.instructions.length] = abi.encode(tokenAddress, uint256(0), transferCallData);

        bytes memory nonceCallData = abi.encodeWithSelector(this.markNonce.selector, nonce);
        unpackedInstructions[intent.instructions.length + 1] = abi.encode(address(this), 0, nonceCallData);

        return (abi.encode(VALIDATION_APPROVED), unpackedInstructions);
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
