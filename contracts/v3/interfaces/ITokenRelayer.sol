// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

interface ITokenRelayer {
    function transferEth(uint256 amount) external;

    function transferERC20(address token, uint256 amount) external;

    function transferERC20From(address from, address token, uint256 amount) external;
}
