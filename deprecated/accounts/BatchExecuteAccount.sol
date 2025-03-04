// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {UserIntent} from "./../interfaces/UserIntent.sol";
import {IStandard} from "./../interfaces/IStandard.sol";
import {IAccount} from "./../interfaces/IAccount.sol";

contract BatchExecuteAccount is IAccount {

    bytes4 public constant VALIDATION_APPROVED = 0x00000001;

    function executeUserIntent(UserIntent calldata intent) external returns (bytes memory) {
        require(intent.sender == address(this), "intent sender is not this account");
        IStandard standard = IStandard(intent.standard);

        bytes4 validationResult = standard.validateUserIntent(intent);
        require(validationResult == VALIDATION_APPROVED, "validation failed");

        (, bytes[] memory instructions) = standard.unpackOperations(intent);
        _executeBatch(instructions);

        return new bytes(0);
    }

    function _executeBatch(bytes[] memory instructions) internal {
        for (uint256 i = 0; i < instructions.length; i++) {
            _execute(instructions[i]);
        }
    }

    function _execute(bytes memory instruction) internal {
        (address dest, uint256 value, bytes memory data) = abi.decode(instruction, (address, uint256, bytes));

        (bool success, bytes memory result) = dest.call{value: value, gas: gasleft()}(data);
        if (!success) {
            assembly {
                revert(add(result, 32), result)
            }
        }
    }

    receive() external payable {}
}
