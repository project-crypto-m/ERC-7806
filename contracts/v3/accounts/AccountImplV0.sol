// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IERC20} from "openzeppelin/token/ERC20/IERC20.sol";
import {StandardRegistry} from "./../../StandardRegistry.sol";
import {IStandard} from "./../interfaces/IStandard.sol";
import {ITokenRelayer} from "./../interfaces/ITokenRelayer.sol";
import {SelfExecutableAccount} from "./SelfExecutableAccount.sol";

contract AccountImplV0 is SelfExecutableAccount {
    string public constant DESCRIPTION = "Account with Batch Execution, Standard Registry and Self-Standard";
    string public constant VERSION = "0.0.0";
    string public constant AUTHOR = "hellohanchen";

    StandardRegistry public constant REGISTRY = StandardRegistry(0xa6673924437D5864488CEC4B8fa1654226bb1E8D);
    bytes4 public constant VALIDATION_APPROVED = 0x00000001;
    bytes4 public constant VALIDATION_DENIED = 0x00000000;

    function executeOtherIntent(bytes calldata intent, address standard) override internal returns (bytes memory) {
        require(REGISTRY.isRegistered(address(this), standard), "Standard not registered");
        // standard validation and unpack
        (bytes4 validationCode, bytes[] memory instructions) = IStandard(standard).unpackOperations(intent);
        require(validationCode == VALIDATION_APPROVED, "Validation failed");

        // batch execute
        for (uint256 i = 0; i < instructions.length; i++) {
            (address dest, uint256 value, bytes memory data) = abi.decode(instructions[i], (address, uint256, bytes));

            (bool success,) = dest.call{value : value, gas : gasleft()}(data);
            if (!success) {
                revert SelfExecutableAccount.ExecutionError();
            }
        }

        return new bytes(0);
    }

    receive() external payable {}
}
