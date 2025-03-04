// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MessageHashUtils} from "openzeppelin/utils/cryptography/MessageHashUtils.sol";
import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";

contract StandardRegistry {
    using ECDSA for bytes32;

    event StandardRegistered(address, address);
    event StandardUnregistered(address, address);

    mapping(bytes32 => bool) _nonces;
    mapping(bytes32 => bool) _registrations;

    function permit(bool registering, address signer, address standard, uint256 nonce, bytes calldata signature) external {
        bytes32 compositeKey = keccak256(abi.encodePacked(signer, nonce));
        require(!_nonces[compositeKey], "Invalid nonce");

        bytes32 permitHash = keccak256(abi.encode(registering, standard, nonce));
        bytes32 messageHash = MessageHashUtils.toEthSignedMessageHash(permitHash);
        require(signer == messageHash.recover(signature), "Invalid signature");

        _process(registering, signer, standard, nonce);
    }

    function update(bool registering, address standard, uint256 nonce) external {
        address signer = msg.sender;
        bytes32 compositeKey = keccak256(abi.encodePacked(signer, nonce));
        require(!_nonces[compositeKey], "Invalid nonce");

        _process(registering, signer, standard, nonce);
    }

    function isNonceUsed(address signer, uint256 nonce) external view returns (bool) {
        bytes32 compositeKey = keccak256(abi.encodePacked(signer, nonce));
        return _nonces[compositeKey];
    }

    function isRegistered(address signer, address standard) external view returns (bool) {
        bytes32 compositeKey = keccak256(abi.encodePacked(signer, standard));

        return _registrations[compositeKey];
    }

    function _process(bool registering, address signer, address standard, uint256 nonce) internal {
        bytes32 compositeKey = keccak256(abi.encodePacked(signer, standard));

        if (registering) {
            _registrations[compositeKey] = true;
            emit StandardRegistered(signer, standard);
        } else {
            _registrations[compositeKey] = false;
            emit StandardUnregistered(signer, standard);
        }

        compositeKey = keccak256(abi.encodePacked(signer, nonce));
        _nonces[compositeKey] = true;
    }
}
