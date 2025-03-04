// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract ICS3Header {
    struct UnpackedHeader {
        bytes32 header;
        bytes nestedHeader;
        uint64 timestamp;
        uint16 numOutTokens;
        uint16 numSignedIns;
        address solver;
    }

    // helper function to unpack the
    function unpackHeader(bytes calldata header) external pure returns (UnpackedHeader memory) {
        require(header.length >= 32, "Invalid ICS3 singleton header");

        uint64 timestamp = uint64(bytes8(header[:8]));
        uint16 numOutTokens = uint16(bytes2(header[8:10]));
        uint16 numInstructions = uint16(bytes2(header[10:12]));
        address solver = address(bytes20(header[12:32]));

        return UnpackedHeader(bytes32(header[:32]), header[32:], timestamp, numOutTokens, numOutTokens + numInstructions, solver);
    }
}