/* solhint-disable func-name-mixedcase */
/* solhint-disable const-name-snakecase */

import "forge-std/Test.sol";
import {MessageHashUtils} from "openzeppelin/utils/cryptography/MessageHashUtils.sol";
import {ICS1} from "./../../../contracts/standards/ICS1.sol";
import {UserIntent} from "./../../../contracts/interfaces/UserIntent.sol";
import {TestERC20} from "./../../../contracts/test/TestERC20.sol";
import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";

contract ICS1Test is Test {
    using ECDSA for bytes32;

    address public account;
    uint256 public accountKey;
    ICS1 public standard;
    TestERC20 public erc20;

    function setUp() public {
        (account, accountKey) = makeAddrAndKey("account");
        standard = new ICS1();
        erc20 = new TestERC20();
    }

    function test_validateIntent() public {
        bytes[] memory instructions = new bytes[](0);

        uint256 nonce = 1;
        uint256 timestamp = block.timestamp + 1000000000000;
        uint256 amount = 1000000;
        bytes memory header = abi.encode(nonce, timestamp, address(erc20), amount);

        bytes32 intentHash = keccak256(abi.encode(header, standard, instructions, block.chainid));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(accountKey, MessageHashUtils.toEthSignedMessageHash(intentHash));
        bytes memory signature = abi.encodePacked(r, s, v);
        bytes[] memory signatures = new bytes[](1);
        signatures[0] = signature;

        UserIntent memory intent;
        intent.sender = account;
        intent.standard = address(standard);
        intent.header = header;
        intent.instructions = instructions;
        intent.signatures = signatures;

        (bytes4 validationResult) = standard.validateUserIntent(intent);
        assertEq(validationResult, standard.VALIDATION_APPROVED());
    }
}
