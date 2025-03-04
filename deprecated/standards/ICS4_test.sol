// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {UserIntent} from "./../interfaces/UserIntent.sol";
import {IStandard} from "./../interfaces/IStandard.sol";
import {IAccount} from "./../interfaces/IAccount.sol";

contract ICS4 is IStandard {
    string public constant ICS_NUMBER = "0000010000000000";
    string public constant DESCRIPTION = "Self-Relay Execution Standard";
    string public constant VERSION = "0.0.0";
    string public constant AUTHOR = "hellohanchen";

    bytes4 public constant VALIDATION_APPROVED = 0x00000001;
    bytes4 public constant VALIDATION_DENIED = 0x00000000;
    bytes4 public constant IACCOUNT_EXECUTE_USER_INTENT_SELECTOR = IAccount.executeUserIntent.selector;

    function validateUserIntent(UserIntent calldata intent) external view returns (bytes4) {
        if (intent.sender != tx.origin) {
            return VALIDATION_DENIED;
        }

        return VALIDATION_APPROVED;
    }

    function unpackOperations(UserIntent calldata intent) external view returns (bytes memory, bytes[] memory) {
        if (intent.sender != tx.origin) {
            return (abi.encode(VALIDATION_DENIED), new bytes[](0));
        }

        bytes[] memory instructions = intent.instructions;
        return (abi.encode(VALIDATION_APPROVED), instructions);
    }

    function sampleNestedIntent(address relayer) external view returns (bytes memory, bytes[] memory) {
        bytes[] memory instructions = new bytes[](1);
        instructions[0] = abi.encode(relayer, address(this));

        return ("0x1", instructions);
    }

    function executeUserIntent(UserIntent calldata intent) external returns (bytes memory) {
        bytes memory executeCallData = abi.encodeWithSelector(IACCOUNT_EXECUTE_USER_INTENT_SELECTOR, intent);

        (, bytes memory result) = intent.sender.call{value: 0, gas: gasleft()}(executeCallData);
        return result;
    }

    receive() external payable {}
}
