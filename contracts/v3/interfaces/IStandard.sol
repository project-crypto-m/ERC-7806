// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

interface IStandard {
    function validateUserIntent(bytes calldata intent) external view returns (bytes4);

    // construct executable operations from intent, it is highly RECOMMENDED to include validation logic within this
    function unpackOperations(bytes calldata intent) external view returns (bytes4, bytes[] memory);
}
