// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {StandardRegistry} from "./../StandardRegistry.sol";
import {UserIntent} from "./../interfaces/UserIntent.sol";
import {IStandard} from "./../interfaces/IStandard.sol";
import {IAccount} from "./../interfaces/IAccount.sol";
import {Initializable} from "openzeppelin/proxy/utils/Initializable.sol";

contract InitializableRegistryBatchExecuteAccount is IAccount, Initializable {
    string public constant NAME = "Initializable Account with Batch Execution and Standard Registry";
    string public constant VERSION = "0.0.0";
    string public constant AUTHOR = "hellohanchen";

    StandardRegistry public constant REGISTRY = StandardRegistry(0x36FA4784075226b2F4518BA9Ce53c01b93B21c07);  // Mekong
    bytes4 public constant VALIDATION_APPROVED = 0x00000001;

    constructor() {
        _disableInitializers();
    }

    /**
     * @dev The _entryPoint member is immutable, to reduce gas consumption.  To upgrade EntryPoint,
     * a new implementation of SimpleAccount must be deployed with the new EntryPoint address, then upgrading
     * the implementation by calling `upgradeTo()`
     */
    function initialize(bytes[] memory instructions) public virtual initializer {
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
    }

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
