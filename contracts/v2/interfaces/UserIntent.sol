// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * User Intent struct
 * @param sender the sender account of this intent.
 * @param standard the standard of this intent
 * @param header the metadata of this intent
 * @param instructions the content of this intent
 * @param signatures the signatures provided with this intent
 */
struct UserIntent {
    address sender;
    address standard;
    bytes headers;
    bytes instructions;
    bytes signatures;
}
