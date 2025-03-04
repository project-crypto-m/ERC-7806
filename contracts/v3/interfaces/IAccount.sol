// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

interface IAccount {
    function executeUserIntent(bytes calldata intent) external returns (bytes memory);
}
