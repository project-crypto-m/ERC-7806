/* solhint-disable func-name-mixedcase */
/* solhint-disable const-name-snakecase */

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {MessageHashUtils} from "openzeppelin/utils/cryptography/MessageHashUtils.sol";
import {ICS3} from "./../../../contracts/standards/ICS3_test.sol";
import {UserIntent} from "./../../../contracts/interfaces/UserIntent.sol";
import {TestERC20} from "./../../../contracts/test/TestERC20.sol";
import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";

contract ICS3Test is Test {
    using ECDSA for bytes32;

    address public account;
    uint256 public accountKey;
    ICS3 public standard;
    TestERC20 public erc20;

    function setUp() public {
        (account, accountKey) = makeAddrAndKey("account");
        standard = new ICS3();
        erc20 = new TestERC20();
        erc20.mint(account, 1000);
    }

    function test_unpackHeader() public {
        bytes memory outerHeader = new bytes(0);
        bytes memory nestedHeader = new bytes(0);

        bytes memory testHeader = abi.encode(outerHeader, nestedHeader);

        // invalid header length
        vm.expectRevert("Invalid ICS3 singleton header");
        standard.unpackHeader(testHeader);

        // valid header
        uint256 nonce = 0;
        uint256 timestamp = 1234;
        outerHeader = abi.encode(nonce, timestamp, uint256(1), uint256(2), address(standard));
        testHeader = abi.encode(outerHeader, nestedHeader);

        // (bytes memory h1, bytes memory h2, uint256 n, uint256 t, uint256 o, uint256 i, address s) = standard.unpackHeader(testHeader);
        ICS3.UnpackedHeader memory unpackedHeader = standard.unpackHeader(testHeader);
        assertEq(unpackedHeader.header, outerHeader);
        assertEq(unpackedHeader.nestedHeader, nestedHeader);
        assertEq(unpackedHeader.nonce, nonce);
        assertEq(unpackedHeader.timestamp, timestamp);
        assertEq(unpackedHeader.numOutTokens, 1);
        assertEq(unpackedHeader.numSignedIns, 3);
        assertEq(unpackedHeader.solver, address(standard));
    }

    function test_validateIntent_beforeHeader() public {
        bytes[] memory instructions = new bytes[](0);

        bytes memory header = "";
        bytes[] memory signatures = new bytes[](0);

        UserIntent memory intent;
        intent.sender = tx.origin;
        intent.header = header;
        intent.instructions = instructions;
        intent.signatures = signatures;

        // wrong standard
        intent.standard = address(0);
        vm.expectRevert("Not this standard");
        standard.validateUserIntent(intent);

        intent.standard = address(standard);

        // too many instructions
        intent.instructions = new bytes[](129);
        vm.expectRevert("Too many instructions");
        standard.validateUserIntent(intent);

        intent.instructions = instructions;

        // not enough signatures
        vm.expectRevert("At least 1 signature is needed");
        standard.validateUserIntent(intent);
    }

    function test_validateIntent_invalidHeader() public {
        bytes[] memory instructions = new bytes[](0);
        bytes[] memory signatures = new bytes[](1);

        uint256 nonce = 0;
        uint256 timestamp = block.timestamp - 1;
        bytes memory outerHeader = abi.encode(nonce, timestamp, uint256(1), uint256(2), address(standard));
        bytes memory header = abi.encode(outerHeader, new bytes(0));

        UserIntent memory intent;
        intent.sender = tx.origin;
        intent.standard = address(standard);
        intent.header = header;
        intent.instructions = instructions;
        intent.signatures = signatures;

        // timestamp too small
        vm.expectRevert("Intent expired");
        standard.validateUserIntent(intent);

        // nonce used
        timestamp = block.timestamp + 1;
        outerHeader = abi.encode(nonce, timestamp, uint256(1), uint256(2), address(standard));
        header = abi.encode(outerHeader, new bytes(0));
        intent.header = header;
        vm.prank(tx.origin);
        standard.markNonce(nonce);
        vm.expectRevert("Nonce used");
        standard.validateUserIntent(intent);

        // not enough instructions
        nonce = nonce + 1;
        outerHeader = abi.encode(nonce, timestamp, uint256(1), uint256(2), address(standard));
        header = abi.encode(outerHeader, new bytes(0));
        intent.header = header;
        vm.expectRevert("Not enough instructions");
        standard.validateUserIntent(intent);
    }


    function test_validateIntent_invalidInstruction() public {
        uint256 nonce = 0;
        uint256 timestamp = block.timestamp + 1;
        bytes memory outerHeader = abi.encode(nonce, timestamp, uint256(1), uint256(1), address(standard));
        bytes memory header = abi.encode(outerHeader, new bytes(0));
        bytes[] memory signatures = new bytes[](1);

        bytes[] memory instructions = new bytes[](2);  // empty instructions

        UserIntent memory intent;
        intent.sender = tx.origin;
        intent.standard = address(standard);
        intent.header = header;
        intent.instructions = instructions;
        intent.signatures = signatures;

    }
}
