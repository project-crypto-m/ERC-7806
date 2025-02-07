/* solhint-disable func-name-mixedcase */
/* solhint-disable const-name-snakecase */

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {MessageHashUtils} from "openzeppelin/utils/cryptography/MessageHashUtils.sol";
import {PartialTokenSwapStandard} from "./../../../../contracts/v3/standards/PartialTokenSwapStandard.sol";
import {TestERC20} from "./../../../../contracts/test/TestERC20.sol";
import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";

contract ICS4Test is Test {
    using ECDSA for bytes32;

    address public account;
    uint256 public accountKey;
    address public solver;
    uint256 public solverKey;
    PartialTokenSwapStandard public standard;
    TestERC20 public erc20;

    function setUp() public {
        (account, accountKey) = makeAddrAndKey("account");
        (solver, solverKey) = makeAddrAndKey("solver");
        standard = new PartialTokenSwapStandard();
        erc20 = new TestERC20();
    }

    function test_validateIntent_success() public {
        erc20.mint(account, 1);

        // no solver assigned
        bytes memory content = bytes.concat(bytes1(0x00), bytes3(0x000000), bytes8(uint64(block.timestamp + 1)), bytes20(address(0x0)), bytes20(address(erc20)), bytes16(uint128(1)), bytes20(address(erc20)), bytes16(uint128(0)));

        bytes32 intentHash = keccak256(abi.encode(content, address(standard), block.chainid));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(accountKey, MessageHashUtils.toEthSignedMessageHash(intentHash));
        bytes memory signature = abi.encodePacked(r, s, v);

        // order limit exceed
        bytes memory intent = bytes.concat(bytes20(address(account)), bytes20(address(standard)), bytes2(uint16(32)), bytes2(uint16(88)), bytes2(uint16(65)), content, bytes16(uint128(1)), signature);

        bytes4 code = standard.validateUserIntent(intent);
        assertEq(code, standard.VALIDATION_APPROVED_SENDER_ONLY());

        // self-solved
        content = bytes.concat(bytes1(0x00), bytes3(0x000000), bytes8(uint64(block.timestamp + 1)), bytes20(address(account)), bytes20(address(erc20)), bytes16(uint128(1)), bytes20(address(erc20)), bytes16(uint128(0)));

        intentHash = keccak256(abi.encode(content, address(standard), block.chainid));
        (v, r, s) = vm.sign(accountKey, MessageHashUtils.toEthSignedMessageHash(intentHash));
        signature = abi.encodePacked(r, s, v);

        intent = bytes.concat(bytes20(address(account)), bytes20(address(standard)), bytes2(uint16(32)), bytes2(uint16(88)), bytes2(uint16(65)), content, bytes16(uint128(1)), signature);

        code = standard.validateUserIntent(intent);
        assertEq(code, standard.VALIDATION_APPROVED());

        // with solver
        content = bytes.concat(bytes1(0x00), bytes3(0x000000), bytes8(uint64(block.timestamp + 1)), bytes20(address(solver)), bytes20(address(erc20)), bytes16(uint128(1)), bytes20(address(erc20)), bytes16(uint128(0)));

        intentHash = keccak256(abi.encode(content, address(standard), block.chainid));
        (v, r, s) = vm.sign(accountKey, MessageHashUtils.toEthSignedMessageHash(intentHash));
        signature = abi.encodePacked(r, s, v);

        intent = bytes.concat(bytes20(address(account)), bytes20(address(standard)), bytes2(uint16(32)), bytes2(uint16(88)), bytes2(uint16(130)), content, bytes16(uint128(1)), signature);

        intentHash = keccak256(abi.encode(intentHash, address(0)));
        (v, r, s) = vm.sign(solverKey, MessageHashUtils.toEthSignedMessageHash(intentHash));
        signature = abi.encodePacked(r, s, v);
        intent = bytes.concat(intent, signature);

        code = standard.validateUserIntent(intent);
        assertEq(code, standard.VALIDATION_APPROVED());
    }

    function test_validateIntent_failure_validations() public {
        // not this address
        bytes memory intent = bytes.concat(bytes20(address(0x1234)), bytes20(address(0x5678)));
        vm.expectRevert("Not this standard");
        standard.validateUserIntent(intent);

        // invalid header length
        intent = bytes.concat(bytes20(address(0x1234)), bytes20(address(standard)), bytes2(uint16(33)), bytes2(uint16(0)), bytes2(uint16(0)));
        vm.expectRevert("Invalid header length");
        standard.validateUserIntent(intent);

        // intent too short
        intent = bytes.concat(bytes20(address(0x1234)), bytes20(address(standard)), bytes2(uint16(32)), bytes2(uint16(0)), bytes2(uint16(0)));
        vm.expectRevert("Not enough intent length");
        standard.validateUserIntent(intent);

        // invalid full order instruction length
        intent = bytes.concat(bytes20(address(0x1234)), bytes20(address(standard)), bytes2(uint16(32)), bytes2(uint16(75)), bytes2(uint16(65)), bytes1(0x01), new bytes(200));
        vm.expectRevert("Invalid full order instruction length");
        standard.validateUserIntent(intent);

        // invalid partial order instruction length
        intent = bytes.concat(bytes20(address(0x1234)), bytes20(address(standard)), bytes2(uint16(32)), bytes2(uint16(75)), bytes2(uint16(65)), bytes1(0x00), new bytes(200));
        vm.expectRevert("Invalid partial order instruction length");
        standard.validateUserIntent(intent);

        // invalid signature length
        intent = bytes.concat(bytes20(address(0x1234)), bytes20(address(standard)), bytes2(uint16(32)), bytes2(uint16(72)), bytes2(uint16(66)), bytes1(0x01), new bytes(200));
        vm.expectRevert("Invalid signature length");
        standard.validateUserIntent(intent);

        // intent expired
        intent = bytes.concat(bytes20(address(0x1234)), bytes20(address(standard)), bytes2(uint16(32)), bytes2(uint16(72)), bytes2(uint16(65)), bytes1(0x01), bytes3(0x000000), bytes8(uint64(block.timestamp - 1)), new bytes(200));
        vm.expectRevert("Intent expired");
        standard.validateUserIntent(intent);

        // not a contract
        intent = bytes.concat(bytes20(address(0x1234)), bytes20(address(standard)), bytes2(uint16(32)), bytes2(uint16(72)), bytes2(uint16(65)), bytes1(0x01), bytes3(0x000000), bytes8(uint64(block.timestamp + 1)), bytes20(address(0x0)), bytes20(address(0x2345)), new bytes(200));
        vm.expectRevert();
        standard.validateUserIntent(intent);

        // not ERC20 token
        intent = bytes.concat(bytes20(address(0x1234)), bytes20(address(standard)), bytes2(uint16(32)), bytes2(uint16(72)), bytes2(uint16(65)), bytes1(0x01), bytes3(0x000000), bytes8(uint64(block.timestamp + 1)), bytes20(address(0x0)), bytes20(address(standard)), new bytes(200));
        vm.expectRevert("Not ERC20 token");
        standard.validateUserIntent(intent);

        // insufficient token balance
        intent = bytes.concat(bytes20(address(0x1234)), bytes20(address(standard)), bytes2(uint16(32)), bytes2(uint16(72)), bytes2(uint16(65)), bytes1(0x01), bytes3(0x000000), bytes8(uint64(block.timestamp + 1)), bytes20(address(0x0)), bytes20(address(erc20)), bytes16(uint128(1)), new bytes(200));
        vm.expectRevert("Insufficient token balance");
        standard.validateUserIntent(intent);

        // in token not contract
        intent = bytes.concat(bytes20(address(0x1234)), bytes20(address(standard)), bytes2(uint16(32)), bytes2(uint16(72)), bytes2(uint16(65)), bytes1(0x01), bytes3(0x000000), bytes8(uint64(block.timestamp + 1)), bytes20(address(0x0)), bytes20(address(erc20)), bytes16(uint128(0)), bytes20(address(0x2345)), bytes16(uint128(0)), new bytes(200));
        vm.expectRevert();
        standard.validateUserIntent(intent);

        // in token not ERC20 token
        intent = bytes.concat(bytes20(address(0x1234)), bytes20(address(standard)), bytes2(uint16(32)), bytes2(uint16(72)), bytes2(uint16(65)), bytes1(0x01), bytes3(0x000000), bytes8(uint64(block.timestamp + 1)), bytes20(address(0x0)), bytes20(address(erc20)), bytes16(uint128(0)), bytes20(address(standard)), bytes16(uint128(0)), new bytes(200));
        vm.expectRevert("Not ERC20 token");
        standard.validateUserIntent(intent);
    }

    function test_validateIntent_failure_signatures() public {
        bytes memory content = bytes.concat(bytes1(0x01), bytes3(0x000000), bytes8(uint64(block.timestamp + 1)), bytes20(address(solver)), bytes20(address(erc20)), bytes16(uint128(0)), bytes20(address(erc20)), bytes16(uint128(0)));
        bytes memory intent = bytes.concat(bytes20(address(account)), bytes20(address(standard)), bytes2(uint16(32)), bytes2(uint16(72)), bytes2(uint16(65)), content, new bytes(200));

        bytes32 intentHash = keccak256(abi.encode(content, address(standard), block.chainid));

        // not a signature
        vm.expectRevert();
        standard.validateUserIntent(intent);

        // invalid signature
        (, uint256 randomKey) = makeAddrAndKey("random");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(randomKey, intentHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        intent = bytes.concat(bytes20(address(account)), bytes20(address(standard)), bytes2(uint16(32)), bytes2(uint16(72)), bytes2(uint16(65)), content, signature, new bytes(200));
        vm.expectRevert("Invalid sender signature");
        standard.validateUserIntent(intent);

        // at least 2 signature needed
        (v, r, s) = vm.sign(accountKey, MessageHashUtils.toEthSignedMessageHash(intentHash));
        signature = abi.encodePacked(r, s, v);
        intent = bytes.concat(bytes20(address(account)), bytes20(address(standard)), bytes2(uint16(32)), bytes2(uint16(72)), bytes2(uint16(65)), content, signature);
        vm.expectRevert("At least 2 signatures are needed to assign relayer");
        standard.validateUserIntent(intent);

        // not a solver signature
        (v, r, s) = vm.sign(accountKey, MessageHashUtils.toEthSignedMessageHash(intentHash));
        signature = abi.encodePacked(r, s, v);
        intent = bytes.concat(bytes20(address(account)), bytes20(address(standard)), bytes2(uint16(32)), bytes2(uint16(72)), bytes2(uint16(65)), content, signature, new bytes(200));
        vm.expectRevert();
        standard.validateUserIntent(intent);

        // invalid solver signature
        (v, r, s) = vm.sign(accountKey, MessageHashUtils.toEthSignedMessageHash(intentHash));
        signature = abi.encodePacked(r, s, v);
        intent = bytes.concat(bytes20(address(account)), bytes20(address(standard)), bytes2(uint16(32)), bytes2(uint16(72)), bytes2(uint16(65)), content, signature, signature);
        vm.expectRevert("Invalid solver signature");
        standard.validateUserIntent(intent);
    }

    function test_validateIntent_failure_afterSig() public {
        erc20.mint(account, 1);

        bytes memory content = bytes.concat(bytes1(0x00), bytes3(0x000000), bytes8(uint64(block.timestamp + 1)), bytes20(address(account)), bytes20(address(erc20)), bytes16(uint128(0)), bytes20(address(erc20)), bytes16(uint128(0)));

        bytes32 intentHash = keccak256(abi.encode(content, address(standard), block.chainid));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(accountKey, MessageHashUtils.toEthSignedMessageHash(intentHash));
        bytes memory signature = abi.encodePacked(r, s, v);

        // only 1 signature is needed
        bytes memory intent = bytes.concat(bytes20(address(account)), bytes20(address(standard)), bytes2(uint16(32)), bytes2(uint16(88)), bytes2(uint16(130)), content, bytes16(uint128(1)), signature, signature);
        vm.expectRevert("Only 1 signature is needed");
        standard.validateUserIntent(intent);

        // order limit exceed
        intent = bytes.concat(bytes20(address(account)), bytes20(address(standard)), bytes2(uint16(32)), bytes2(uint16(88)), bytes2(uint16(65)), content, bytes16(uint128(1)), signature);
        vm.expectRevert("Order limit exceeded");
        standard.validateUserIntent(intent);
    }
}
