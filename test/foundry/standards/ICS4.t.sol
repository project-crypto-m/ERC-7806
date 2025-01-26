/* solhint-disable func-name-mixedcase */
/* solhint-disable const-name-snakecase */

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {MessageHashUtils} from "openzeppelin/utils/cryptography/MessageHashUtils.sol";
import {ICS0000010000000000} from "./../../../contracts/standards/ICS4.sol";
import {UserIntent} from "./../../../contracts/interfaces/UserIntent.sol";
import {TestERC20} from "./../../../contracts/test/TestERC20.sol";
import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";

contract ICS4Test is Test {
    using ECDSA for bytes32;

    address public account;
    uint256 public accountKey;
    ICS0000010000000000 public standard;
    TestERC20 public erc20;

    function setUp() public {
        (account, accountKey) = makeAddrAndKey("account");
        standard = new ICS0000010000000000();
        erc20 = new TestERC20();
    }

    function test_validateIntent() public {
        bytes[] memory instructions = new bytes[](0);

        bytes memory header = "";
        bytes[] memory signatures = new bytes[](0);

        UserIntent memory intent;
        intent.sender = tx.origin;
        intent.standard = address(standard);
        intent.header = header;
        intent.instructions = instructions;
        intent.signatures = signatures;

        (bytes4 validationResult) = standard.validateUserIntent(intent);
        assertEq(validationResult, standard.VALIDATION_APPROVED());

        intent.sender = address(0);
        validationResult = standard.validateUserIntent(intent);
        assertEq(validationResult, standard.VALIDATION_DENIED());
    }

    function test_unpackOperations() public {
        bytes[] memory instructions = new bytes[](1);
        instructions[0] = "test";

        bytes memory header = "";
        bytes[] memory signatures = new bytes[](0);

        UserIntent memory intent;
        intent.sender = tx.origin;
        intent.standard = address(standard);
        intent.header = header;
        intent.instructions = instructions;
        intent.signatures = signatures;

        (bytes memory validationResult, bytes[] memory operations) = standard.unpackOperations(intent);
        (bytes4 validationCode) = abi.decode(validationResult, (bytes4));
        assertEq(validationCode, standard.VALIDATION_APPROVED());
        assertEq(1, operations.length);
        assertEq("test", operations[0]);

        intent.sender = address(0);
        (validationResult, operations) = standard.unpackOperations(intent);
        validationCode = abi.decode(validationResult, (bytes4));
        assertEq(validationCode, standard.VALIDATION_DENIED());
        assertEq(0, operations.length);
    }
}
