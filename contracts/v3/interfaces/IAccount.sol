// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IAccount {
    function executeUserIntent(bytes calldata intent) external returns (bytes memory);
}
