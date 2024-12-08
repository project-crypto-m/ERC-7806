// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {UserIntent} from "./UserIntent.sol";

interface IAccount {
    function executeUserIntent(UserIntent calldata intent) external returns (bytes memory);
}
