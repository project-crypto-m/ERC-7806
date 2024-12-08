/* solhint-disable func-name-mixedcase */
/* solhint-disable const-name-snakecase */

import "forge-std/Test.sol";
import {MessageHashUtils} from "openzeppelin/utils/cryptography/MessageHashUtils.sol";
import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";
import {StandardRegistry} from "./../../contracts/StandardRegistry.sol";

contract StandardRegistryTest is Test {
    using ECDSA for bytes32;

    StandardRegistry registry;

    address public account;
    uint256 public accountKey;

    function setUp() public {
        (account, accountKey) = makeAddrAndKey("account");
        registry = new StandardRegistry();
    }

    function test_permit() public {
        bool registering = true;
        address standard = address(0);
        uint256 nonce = 123;
        bytes32 permitHash = keccak256(abi.encode(registering, standard, nonce));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(accountKey, MessageHashUtils.toEthSignedMessageHash(permitHash));
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.startPrank(address(account));

        // wrong signature
        vm.expectRevert();
        registry.permit(registering, address(account), standard, nonce, abi.encodePacked(v, s, r));
        vm.expectRevert("Invalid signature");
        registry.permit(registering, address(0), standard, nonce, signature);

        // register new standard
        vm.expectEmit(true, false, false, true);
        emit StandardRegistry.StandardRegistered(address(account), standard);
        registry.permit(registering, address(account), standard, nonce, signature);

        (bool nonceUsed) = registry.isNonceUsed(address(account), nonce);
        assertEq(nonceUsed, true);

        (bool registered) = registry.isRegistered(address(account), standard);
        assertEq(registered, true);

        vm.expectRevert("Invalid nonce");
        registry.permit(registering, address(account), standard, nonce, signature);

        registering = false;
        nonce = 124;
        permitHash = keccak256(abi.encode(registering, standard, nonce));

        // unregister standard
        (v, r, s) = vm.sign(accountKey, MessageHashUtils.toEthSignedMessageHash(permitHash));
        signature = abi.encodePacked(r, s, v);

        vm.expectEmit(true, false, false, true);
        emit StandardRegistry.StandardUnregistered(address(account), standard);
        registry.permit(registering, address(account), standard, nonce, signature);

        (registered) = registry.isRegistered(address(account), standard);
        assertEq(registered, false);

        vm.stopPrank();
    }

    function test_update() public {
        bool registering = true;
        address standard = address(0);
        uint256 nonce = 123;

        vm.startPrank(address(account));

        // register new standard
        vm.expectEmit(true, false, false, true);
        emit StandardRegistry.StandardRegistered(address(account), standard);
        registry.update(registering, standard, nonce);

        (bool nonceUsed) = registry.isNonceUsed(address(account), nonce);
        assertEq(nonceUsed, true);

        (bool registered) = registry.isRegistered(address(account), standard);
        assertEq(registered, true);

        vm.expectRevert("Invalid nonce");
        registry.update(registering, standard, nonce);

        registering = false;
        nonce = 124;

        // unregister standard
        vm.expectEmit(true, false, false, true);
        emit StandardRegistry.StandardUnregistered(address(account), standard);
        registry.update(registering, standard, nonce);

        (registered) = registry.isRegistered(address(account), standard);
        assertEq(registered, false);

        vm.stopPrank();
    }
}
