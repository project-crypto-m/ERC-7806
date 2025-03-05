// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {MessageHashUtils} from "openzeppelin/utils/cryptography/MessageHashUtils.sol";
import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";

contract StandardRegistryV2 {
    using ECDSA for bytes32;

    event StandardRegistered(address, address);
    event StandardUnregistered(address, address);

    bytes32 public immutable DOMAIN_SEPARATOR;
    bytes32 public immutable SIGNED_DATA_TYPEHASH;

    mapping(bytes32 => bool) _nonces;
    mapping(bytes32 => bool) _registrations;

    constructor() {
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("StandardRegistry")), // Contract name
                keccak256(bytes("2")), // Version
                block.chainid, // Chain ID
                address(this) // Contract address
            )
        );

        SIGNED_DATA_TYPEHASH = keccak256(
            "Permission(bool registering,address standard,uint256 nonce)"
        );
    }

    function permit(bool registering, address signer, address standard, uint256 nonce, bytes calldata signature) external {
        bytes32 compositeKey = keccak256(abi.encodePacked(signer, nonce));
        require(!_nonces[compositeKey], "Invalid nonce");

        // validate signature
        bytes32 structHash = keccak256(
            abi.encode(SIGNED_DATA_TYPEHASH, registering, standard, nonce)
        );
        bytes32 digest = MessageHashUtils.toTypedDataHash(DOMAIN_SEPARATOR, structHash);
        require(signer == digest.recover(signature), "Invalid signature");

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
