// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {UserIntent} from "./UserIntent.sol";

interface IStandard {
    event NonceUsed(address sender, uint256 nonce);

    function validateUserIntent(UserIntent calldata intent) external view returns (bytes4);

    // construct executable operations from intent, it is highly RECOMMENDED to include validation logic within this
    function unpackOperations(UserIntent calldata intent) external view returns (bytes4, bytes[] memory);
}
