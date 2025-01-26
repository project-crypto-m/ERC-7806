// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "openzeppelin/token/ERC20/IERC20.sol";
import {StandardRegistry} from "./../../StandardRegistry.sol";
import {UserIntent} from "./../interfaces/UserIntent.sol";
import {IStandard} from "./../interfaces/IStandard.sol";
import {ITokenRelayer} from "./../interfaces/ITokenRelayer.sol";
import {IAccount} from "./../interfaces/IAccount.sol";

    error ExecutionError(uint256 instructionId);

contract SelfExecutableRegistryAccount is IAccount {
    string public constant DESCRIPTION = "Account with Batch Execution, Standard Registry and Self-Standard";
    string public constant VERSION = "0.0.0";
    string public constant AUTHOR = "hellohanchen";

    StandardRegistry public constant REGISTRY = StandardRegistry(0xa6673924437D5864488CEC4B8fa1654226bb1E8D);
    bytes4 public constant VALIDATION_APPROVED = 0x00000001;
    bytes4 public constant VALIDATION_DENIED = 0x00000000;
    bytes4 public constant IACCOUNT_EXECUTE_USER_INTENT_SELECTOR = IAccount.executeUserIntent.selector;

    function executeUserIntent(UserIntent calldata intent) external returns (bytes memory) {
        require(intent.sender == address(this), "Not intent sender");

        // if the intent is from self, then just execute it
        if (intent.standard == address(this) && tx.origin == address(this)) {
            uint256 numIns = intent.headers.length / 2;
            uint256 start = 0;
            uint256 insLen;
            address dest;
            uint256 value;
            bool success;

            for (uint256 i = 0; i < numIns; i++) {
                insLen = uint16(bytes2(intent.headers[i * 2 : i * 2 + 2]));
                dest = address(bytes20(intent.instructions[start : start + 20]));
                if (bytes1(intent.instructions[start + 20 : start + 22]) == bytes1(0x01)) {
                    value = uint256(bytes32(intent.instructions[start + 22 : start + 54]));
                    (success,) = dest.call{value : value, gas : gasleft()}(intent.instructions[start + 54 : start + 54 + insLen]);
                    start = start + 2;
                } else {
                    (success,) = dest.call{value : 0, gas : gasleft()}(intent.instructions[start + 52 : start + 52 + insLen]);
                }

                if (!success) {
                    revert ExecutionError(i);
                }

                start = start + 52 + insLen;
            }

            return new bytes(0);
        }

        require(REGISTRY.isRegistered(address(this), intent.standard), "Standard not registered");
        // standard validation and unpack
        (bytes4 validationCode, bytes[] memory instructions) = IStandard(intent.standard).unpackOperations(intent);
        require(validationCode == VALIDATION_APPROVED, "Validation failed");

        // batch execute
        for (uint256 i = 0; i < instructions.length; i++) {
            (address dest, uint256 value, bytes memory data) = abi.decode(instructions[i], (address, uint256, bytes));

            (bool success,) = dest.call{value : value, gas : gasleft()}(data);
            if (!success) {
                revert ExecutionError(i);
            }
        }

        return new bytes(0);
    }

    function sampleIntent(
        address selfExecutableAccount,
        UserIntent[] calldata intents,
        address tokenRelayer,
        bytes calldata outTokens
    ) external pure returns (UserIntent memory, bytes memory) {
        bytes memory instructions;
        bytes memory header;
        bytes memory insData;

        for (uint256 i = 0; i < intents.length; i++) {
            insData = abi.encodeWithSelector(IACCOUNT_EXECUTE_USER_INTENT_SELECTOR, intents[i]);
            header = bytes.concat(header, bytes2(uint16((insData.length) & 0xFFFF)));
            instructions = bytes.concat(instructions, bytes20(intents[i].sender), bytes1(0x00), insData);
        }

        uint256 numTokens = outTokens.length / 52;
        for (uint256 i = 0; i < numTokens; i++) {
            address tokenAddress = address(bytes20(outTokens[i * 52 : i * 52 + 20]));
            uint256 amount = uint256(bytes32(outTokens[i * 52 + 20 : i * 52 + 52]));

            if (tokenAddress == address(0)) {
                insData = abi.encodeWithSelector(ITokenRelayer.transferEth.selector, amount);
            } else {
                insData = abi.encodeWithSelector(ITokenRelayer.transferERC20.selector, tokenAddress, amount);
            }

            header = bytes.concat(header, bytes2(uint16((insData.length) & 0xFFFF)));
            instructions = bytes.concat(instructions, bytes20(tokenRelayer), bytes1(0x00), insData);
        }

        UserIntent memory result;
        result.sender = selfExecutableAccount;
        result.standard = selfExecutableAccount;
        result.headers = header;
        result.instructions = instructions;
        result.signatures = new bytes(0);

        return (result, abi.encodePacked(selfExecutableAccount, selfExecutableAccount));
    }

    receive() external payable {}
}
