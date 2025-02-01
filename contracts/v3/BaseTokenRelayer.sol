// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "openzeppelin/token/ERC20/IERC20.sol";
import {ITokenRelayer} from "./interfaces/ITokenRelayer.sol";

abstract contract BaseTokenRelayer is ITokenRelayer {
    function transferEth(uint256 amount) external {
        require(address(this).balance >= amount, "Insufficient balance");
        bool success = payable(msg.sender).send(amount);
        require(success, "Failed to send Ether");
    }

    function transferERC20(address token, uint256 amount) external {
        bool success = IERC20(token).transfer(msg.sender, amount);
        require(success, "Failed to send ERC20");
    }

    function transferERC20From(address from, address token, uint256 amount) external {
        require(from == tx.origin || from == address(this), "Can only transfer from tx.origin or this address");
        if (from == tx.origin) {
            bool success = IERC20(token).transferFrom(from, msg.sender, amount);
            require(success, "Failed to send ERC20");
        } else {
            this.transferERC20(token, amount);
        }
    }

    receive() external payable {}
}
