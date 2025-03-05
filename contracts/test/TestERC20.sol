// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.28;

import {ERC20} from "openzeppelin/token/ERC20/ERC20.sol";

contract SwapHereUSDC is ERC20 {
    constructor()
        // solhint-disable-next-line no-empty-blocks
        ERC20("SwapHereUSDC", "shUSDC")
    {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    /**
     * @dev Super unsafe function to set approval for another account
     */
    function approveFor(address owner, address spender, uint256 amount) public returns (bool) {
        _approve(owner, spender, amount);
        return true;
    }

    function decimals() public view override returns (uint8) {
        return 6;
    }
}
