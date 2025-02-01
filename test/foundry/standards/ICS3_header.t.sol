/* solhint-disable func-name-mixedcase */
/* solhint-disable const-name-snakecase */

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {ICS3Header} from "./../../../contracts/standards/ICS3_header.sol";

contract ICS3HeaderTest is Test {
    address public account;
    uint256 public accountKey;
    ICS3Header public standard;

    function setUp() public {
        (account, accountKey) = makeAddrAndKey("account");
        standard = new ICS3Header();
    }

    function test_unpackHeader() public {
        bytes memory nestedHeader = new bytes(0);
        bytes memory testHeader = bytes.concat(new bytes(0), nestedHeader);

        // invalid header length
        vm.expectRevert("Invalid ICS3 singleton header");
        standard.unpackHeader(testHeader);

        // valid header
        uint64 timestamp = 1234;
        bytes memory encoded = abi.encodePacked(timestamp, uint16(1), uint16(2), address(standard));
        assertEq(32, encoded.length);
        bytes32 outerHeader = bytes32(encoded);
        testHeader = bytes.concat(outerHeader, nestedHeader);

        // (bytes memory h1, bytes memory h2, uint256 n, uint256 t, uint256 o, uint256 i, address s) = standard.unpackHeader(testHeader);
        ICS3Header.UnpackedHeader memory unpackedHeader = standard.unpackHeader(testHeader);
        assertEq(unpackedHeader.header, outerHeader);
        assertEq(unpackedHeader.nestedHeader, nestedHeader);
        assertEq(unpackedHeader.timestamp, timestamp);
        assertEq(unpackedHeader.numOutTokens, 1);
        assertEq(unpackedHeader.numSignedIns, 3);
        assertEq(unpackedHeader.solver, address(standard));
    }
}
