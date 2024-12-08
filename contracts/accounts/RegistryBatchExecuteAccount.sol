// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {StandardRegistry} from "./../StandardRegistry.sol";
import {UserIntent} from "./../interfaces/UserIntent.sol";
import {IStandard} from "./../interfaces/IStandard.sol";
import {IAccount} from "./../interfaces/IAccount.sol";

contract RegistryBatchExecuteAccount is IAccount {
    string public constant NAME = "Account with Batch Execution and Standard Registry";
    string public constant VERSION = "0.0.0";
    string public constant AUTHOR = "hellohanchen";

    StandardRegistry public constant REGISTRY = StandardRegistry(0xa6673924437D5864488CEC4B8fa1654226bb1E8D);
    bytes4 public constant VALIDATION_APPROVED = 0x00000001;

    function executeUserIntent(UserIntent calldata intent) external returns (bytes memory) {
        require(intent.sender == address(this), "Not intent sender");
        require(REGISTRY.isRegistered(address(this), intent.standard), "Standard not registered");

        // standard validation
        IStandard standard = IStandard(intent.standard);
        (bytes memory validationResult, bytes[] memory instructions) = standard.unpackOperations(intent);
        (bytes4 validationCode) = abi.decode(validationResult, (bytes4));
        require(validationCode == VALIDATION_APPROVED, "Validation failed");

        // batch execute
        for (uint256 i = 0; i < instructions.length; i++) {
            (address dest, uint256 value, bytes memory data) = abi.decode(instructions[i], (address, uint256, bytes));

            (bool success, bytes memory result) = dest.call{value: value, gas: gasleft()}(data);
            if (!success) {
                assembly {
                    revert(add(result, 32), result)
                }
            }
        }

        return new bytes(0);
    }

    receive() external payable {}
}
