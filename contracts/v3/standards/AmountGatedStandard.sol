// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IStandard} from "./../interfaces/IStandard.sol";

abstract contract AmountGatedStandard is IStandard {
    event AmountUsed(address sender, uint256 hash, uint256 amount);

    mapping(bytes32 => uint256) internal _hashes;

    function getAmount(address sender, uint256 hash) external view returns (uint256) {
        bytes32 compositeKey = keccak256(abi.encode(sender, hash));
        return _hashes[compositeKey];
    }

    function markAmount(uint256 hash, uint256 amount) external {
        bytes32 compositeKey = keccak256(abi.encode(msg.sender, hash));
        _hashes[compositeKey] += amount;

        emit AmountUsed(msg.sender, hash, amount);
    }
}
