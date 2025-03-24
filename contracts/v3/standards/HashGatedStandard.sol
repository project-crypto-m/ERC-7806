// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IStandard} from "./../interfaces/IStandard.sol";

/// @title HashGatedStandard
/// @notice This is an abstract contract that implements the IStandard interface and provides a mechanism to track and validate hashes associated with specific addresses.
/// @dev Each hash MUST be used at most once
abstract contract HashGatedStandard is IStandard {
    /// @notice HashUsed event is emitted when a hash is used
    event HashUsed(address sender, uint256 hash);

    /// @notice _hashes is a mapping that stores the hash used for a specific address
    mapping(bytes32 hash => bool used) internal _hashes;

    /// @notice checkHash is a function that checks if a hash is used
    /// @param sender The address of the sender
    /// @param hash The hash to check
    /// @return result The result of the check
    function checkHash(address sender, uint256 hash) external view returns (bool) {
        bytes32 compositeKey = keccak256(abi.encode(sender, hash));
        return _hashes[compositeKey];
    }

    /// @notice markHash is a function that marks a hash as used
    /// @dev this function can be used to invalidate a hash
    /// @param hash The hash to mark
    function markHash(uint256 hash) external {
        bytes32 compositeKey = keccak256(abi.encode(msg.sender, hash));
        _hashes[compositeKey] = true;

        emit HashUsed(msg.sender, hash);
    }
}
