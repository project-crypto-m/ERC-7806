// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC1155} from "@openzeppelin/contracts/token/ERC1155/IERC1155.sol";
import {ERC165} from "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {Arrays} from "@openzeppelin/contracts/utils/Arrays.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";

contract MarginTokenWrapper is ERC165, IERC1155 {
    using ECDSA for bytes32;
    using Arrays for uint256[];
    using Arrays for address[];

    event Mint(address indexed minter, address indexed account, uint256 id, uint256 amount);
    event LockApproval(address indexed account, address indexed locker, uint256 id, uint256 amount);
    event Lock(address indexed locker, address indexed account, uint256 id, uint256 amount);
    event Unlock(address indexed locker, address indexed account, uint256 id, uint256 amount);
    event Liquidate(address indexed locker, address indexed account, address indexed to, uint256 id, uint256 amount);
    event Approval(address indexed account, address indexed spender, uint256 id, uint256 amount);
    event Transfer(address indexed from, address indexed to, uint256 id, uint256 amount);
    event Burn(address indexed burner, address indexed to, uint256 id, uint256 amount);

    mapping(uint256 id => uint256 supply) private _supplies;
    mapping(uint256 id => mapping(address account => uint256)) private _balances;
    mapping(uint256 id => mapping(address account => uint256)) private _lockedBalances;
    mapping(uint256 id => mapping(address account => mapping(address locker => uint256 amount))) private _lockedBalancesByLocker;
    mapping(uint256 id => mapping(address account => mapping(address locker => uint256 amount))) private _approvedLockLimitsByLocker;
    mapping(uint256 id => mapping(address account => mapping(address locker => uint256 expiration))) private _approvedLockExpirationsByLocker;
    mapping(uint256 id => mapping(address account => mapping(address spender => uint256 amount))) private _approvedBalancesBySpender;

    bytes32 public immutable DOMAIN_SEPARATOR;
    bytes32 public immutable LOCK_PERMIT_TYPEHASH;
    bytes32 public immutable TRANSFER_PERMIT_TYPEHASH;
    uint256 public constant ETH_ID = 0;

    modifier sufficientUnlockedBalance(address account, uint256 id, uint256 amount) {
        require(_unlockedBalanceOf(account, id) >= amount, "MarginTokenWrapper: insufficient unlocked balance");
        _;
    }

    constructor() {
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("MarginTokenWrapper")), // Contract name
                keccak256(bytes("0.0.0")), // Version
                block.chainid, // Chain ID
                address(this) // Contract address
            )
        );

        LOCK_PERMIT_TYPEHASH = keccak256(
            "LockApproval(address locker,uint256 id,uint256 amount,uint256 expiration)"
        );

        TRANSFER_PERMIT_TYPEHASH = keccak256(
            "TransferApproval(address spender,uint256 id,uint256 amount)"
        );
    }

    function supportsInterface(bytes4 interfaceId) public view override(ERC165, IERC165) returns (bool) {
        return
            interfaceId == type(IERC1155).interfaceId ||
            super.supportsInterface(interfaceId);
    }

    // Token id mapping
    function addressToId(address token) public pure returns (uint256) {
        return uint256(uint160(token));
    }
    function addressAndIdToId(address token, uint96 id) public pure returns (uint256) {
        return (uint256(uint160(token)) << 160) | id;
    }
    function idToAddress(uint256 id) public pure returns (address) {
        return address(uint160(id));
    }
    function idToAddressAndId(uint256 id) public pure returns (address, uint96) {
        return (address(uint160(id >> 160)), uint96(id & type(uint96).max));
    }

    // Mint
    function mintFromETH() public payable {
        _mint(msg.sender, msg.sender, ETH_ID, msg.value);
    }

    function mintFromETHTo(address account) public payable {
        _mint(msg.sender, account, ETH_ID, msg.value);
    }

    function mintFromERC20(address token, uint256 amount) public {
        bool success = IERC20(token).transferFrom(msg.sender, address(this), amount);
        require(success, "Mint: ERC20 transfer failed");
        _mint(msg.sender, msg.sender, addressToId(token), amount);
    }

    function mintFromERC20To(address account, address token, uint256 amount) public {
        bool success = IERC20(token).transferFrom(msg.sender, address(this), amount);
        require(success, "Mint: ERC20 transfer failed");
        _mint(msg.sender, account, addressToId(token), amount);
    }

    function mintFromERC721(address token, uint256 id) public {
        require(id < type(uint96).max, "Mint: ERC721 ID too large");
        IERC721(token).safeTransferFrom(msg.sender, address(this), id);
        _mint(msg.sender, msg.sender, addressAndIdToId(token, uint96(id)), 1);
    }

    function mintFromERC721To(address account, address token, uint256 id) public {
        require(id < type(uint96).max, "Mint: ERC721 ID too large");
        IERC721(token).safeTransferFrom(msg.sender, account, id);
        _mint(msg.sender, account, addressAndIdToId(token, uint96(id)), 1);
    }
    
    function mintFromERC1155(address token, uint256 id, uint256 amount, bytes calldata data) public {
        require(id < type(uint96).max, "Mint: ERC1155 ID too large");
        IERC1155(token).safeTransferFrom(msg.sender, address(this), id, amount, data);
        _mint(msg.sender, msg.sender, addressAndIdToId(token, uint96(id)), amount);
    }

    function mintFromERC1155To(address account, address token, uint256 id, uint256 amount, bytes calldata data) public {
        require(id < type(uint96).max, "Mint: ERC1155 ID too large");
        IERC1155(token).safeTransferFrom(msg.sender, account, id, amount, data);
        _mint(msg.sender, account, addressAndIdToId(token, uint96(id)), amount);
    }

    function _mint(address minter, address account, uint256 id, uint256 amount) internal {
        _balances[id][account] += amount;
        _supplies[id] += amount;
        emit Mint(minter, account, id, amount);
    }

    // LockApproval
    function approveLock(address locker, uint256 id, uint256 amount, uint256 expiration) public {
        require(expiration > block.timestamp, "LockApproval: expiration must be in the future");
        _approveLock(msg.sender, locker, id, amount, expiration);
    }

    function permitLock(address account, address locker, uint256 id, uint256 amount, uint256 expiration, bytes calldata signature) public {
        require(expiration > block.timestamp, "LockApproval: expiration must be in the future");
        bytes32 structHash = keccak256(
            abi.encode(LOCK_PERMIT_TYPEHASH, locker, id, amount, expiration)
        );
        bytes32 digest = MessageHashUtils.toTypedDataHash(DOMAIN_SEPARATOR, structHash);
        require(account == ECDSA.recover(digest, signature), "LockApproval: invalid signature");
        _approveLock(account, locker, id, amount, expiration);
    }
    
    function _approveLock(address account, address locker, uint256 id, uint256 amount, uint256 expiration) internal {
        _approvedLockLimitsByLocker[id][account][locker] += amount;
        _approvedLockExpirationsByLocker[id][account][locker] = expiration;
        emit LockApproval(account, locker, id, amount);
    }
    
    // Lock
    function lock(address account, uint256 id, uint256 amount) public {
        require(account != msg.sender, "Lock: cannot lock to self");
        _lock(msg.sender, account, id, amount);
    }

    function _lock(address locker, address account, uint256 id, uint256 amount) internal sufficientUnlockedBalance(account, id, amount) {
        require(_lockLimitOf(account, id, locker) >= amount, "Lock: insufficient lock limit");
        require(_lockExpirationOf(account, id, locker) > block.timestamp, "Lock: lock approval expired");
        _lockedBalances[id][account] += amount;
        _lockedBalancesByLocker[id][account][locker] += amount;
        emit Lock(locker, account, id, amount);
    }

    // Unlock
    function unlock(address account, uint256 id, uint256 amount) public {
        _unlock(msg.sender, account, id, amount);
    }

    function unlockAll(address account, uint256 id) public {
        _unlock(msg.sender, account, id, _lockedBalanceByLocker(account, id, msg.sender));
    }

    function selfUnlock(address locker, uint256 id, uint256 amount) public {
        require(_lockExpirationOf(msg.sender, id, locker) < block.timestamp, "Unlock: lock approval not expired");
        _unlock(locker, msg.sender, id, amount);
    }

    function selfUnlockAll(address locker, uint256 id) public {
        require(_lockExpirationOf(msg.sender, id, locker) < block.timestamp, "Unlock: lock approval not expired");
        _unlock(locker, msg.sender, id, _lockedBalanceByLocker(msg.sender, id, locker));
    }

    function _unlock(address locker, address account, uint256 id, uint256 amount) internal {
        require(_lockedBalanceByLocker(account, id, locker) >= amount, "Unlock: insufficient locked balance by locker");
        _lockedBalances[id][account] -= amount;
        _lockedBalancesByLocker[id][account][locker] -= amount;
        emit Unlock(locker, account, id, amount);
    }

    // Liquidate
    function liquidate(address account, uint256 id, uint256 amount) public {
        _liquidate(msg.sender, account, msg.sender, id, amount);
    }

    function liquidateAll(address account, uint256 id) public {
        _liquidate(msg.sender, account, msg.sender, id, _lockedBalanceByLocker(account, id, msg.sender));
    }

    function liquidateTo(address account, address to, uint256 id, uint256 amount) public {
        _liquidate(msg.sender, account, to, id, amount);
    }

    function liquidateAllTo(address account, address to, uint256 id) public {
        _liquidate(msg.sender, account, to, id, _lockedBalanceByLocker(account, id, msg.sender));
    }

    function _liquidate(address locker, address account, address to, uint256 id, uint256 amount) internal {
        require(_lockedBalanceByLocker(account, id, locker) >= amount, "Liquidate: insufficient locked balance by locker");
        _lockedBalances[id][account] -= amount;
        _lockedBalancesByLocker[id][account][locker] -= amount;
        _transferFrom(account, to, id, amount);
        emit Liquidate(locker, account, to, id, amount);
    }

    // Approve
    function approve(address spender, uint256 id, uint256 amount) public {
        _approve(msg.sender, spender, id, amount);
    }

    function permit(address account, address spender, uint256 id, uint256 amount, bytes calldata signature) public {
        bytes32 structHash = keccak256(
            abi.encode(TRANSFER_PERMIT_TYPEHASH, spender, id, amount)
        );
        bytes32 digest = MessageHashUtils.toTypedDataHash(DOMAIN_SEPARATOR, structHash);
        require(account == ECDSA.recover(digest, signature), "TransferApproval: invalid signature");
        _approve(account, spender, id, amount);
    }

    function _approve(address account, address spender, uint256 id, uint256 amount) internal {
        _approvedBalancesBySpender[id][account][spender] += amount;
        emit Approval(account, spender, id, amount);
    }

    function setApprovalForAll(address /* spender */, bool /* approved */) public pure override {
        require(false, "setApprovalForAll: not implemented");
    }

    function isApprovedForAll(address /* account */, address /* spender */) public pure override returns (bool) {
        return false;
    }

    // Transfer
    function transfer(address to, uint256 id, uint256 amount) public sufficientUnlockedBalance(msg.sender, id, amount) {
        _transferFrom(msg.sender, to, id, amount);
    }

    function transferFrom(address from, address to, uint256 id, uint256 amount) public sufficientUnlockedBalance(from, id, amount) {
        require(_allowanceOf(from, id, msg.sender) >= amount, "Transfer: insufficient allowance");
        _transferFrom(from, to, id, amount);
        _approvedBalancesBySpender[id][from][msg.sender] -= amount;
    }
    
    function safeTransferFrom(address from, address to, uint256 id, uint256 amount, bytes calldata /* data */) public sufficientUnlockedBalance(from, id, amount) {
        require(_allowanceOf(from, id, msg.sender) >= amount, "Transfer: insufficient allowance");
        _transferFrom(from, to, id, amount);
        _approvedBalancesBySpender[id][from][msg.sender] -= amount;
    }

    function safeBatchTransferFrom(address from, address to, uint256[] calldata ids, uint256[] calldata amounts, bytes calldata data) public {
        require(ids.length == amounts.length, "Transfer: ids and amounts length mismatch");
        for (uint256 i = 0; i < ids.length; i++) {
            safeTransferFrom(from, to, ids[i], amounts[i], data);
        }
    }

    function _transferFrom(address from, address to, uint256 id, uint256 amount) internal {
        require(_balanceOf(from, id) >= amount, "Transfer: insufficient balance");
        _balances[id][from] -= amount;
        _balances[id][to] += amount;
        emit Transfer(from, to, id, amount);
    }

    // Burn
    function burnETH(uint256 amount) public payable sufficientUnlockedBalance(msg.sender, ETH_ID, amount) {
        _burnETH(msg.sender, payable(msg.sender), amount);
    }

    function burnETHTo(address payable to, uint256 amount) public payable sufficientUnlockedBalance(msg.sender, ETH_ID, amount) {
        _burnETH(msg.sender, to, amount);
    }

    function _burnETH(address burner, address payable to, uint256 amount) internal {
        _burn(ETH_ID, amount);
        _balances[ETH_ID][burner] -= amount;
        (bool success, ) = to.call{value: amount}("");
        require(success, "Burn: ETH transfer failed");
        emit Burn(burner, to, ETH_ID, amount);
    }

    function burnERC20(uint256 id, uint256 amount) public sufficientUnlockedBalance(msg.sender, id, amount) {
        _burnERC20(msg.sender, msg.sender, id, amount);
    }

    function burnERC20To(address to, uint256 id, uint256 amount) public sufficientUnlockedBalance(msg.sender, id, amount) {
        _burnERC20(msg.sender, to, id, amount);
    }

    function _burnERC20(address burner, address to, uint256 id, uint256 amount) internal {
        _burn(id, amount);
        _balances[id][burner] -= amount;
        bool success = IERC20(idToAddress(id)).transfer(to, amount);
        require(success, "Burn: ERC20 transfer failed");
        emit Burn(burner, to, id, amount);
    }

    function burnERC721(uint256 id) public sufficientUnlockedBalance(msg.sender, id, 1) {
        _burnERC721(msg.sender, msg.sender, id);
    }

    function burnERC721To(address to, uint256 id) public sufficientUnlockedBalance(msg.sender, id, 1) {
        _burnERC721(msg.sender, to, id);
    }

    function _burnERC721(address burner, address to, uint256 id) internal {
        _burn(id, 1);
        _balances[id][burner] -= 1;
        (address token, uint96 tokenId) = idToAddressAndId(id);
        IERC721(token).safeTransferFrom(address(this), to, tokenId);
        emit Burn(burner, to, id, 1);
    }

    function burnERC1155(uint256 id, uint256 amount) public sufficientUnlockedBalance(msg.sender, id, amount) {
        _burnERC1155(msg.sender, msg.sender, id, amount);
    }
    
    function burnERC1155To(address to, uint256 id, uint256 amount) public sufficientUnlockedBalance(msg.sender, id, amount) {
        _burnERC1155(msg.sender, to, id, amount);
    }

    function _burnERC1155(address burner, address to, uint256 id, uint256 amount) internal {
        _burn(id, amount);
        _balances[id][burner] -= amount;
        (address token, uint96 tokenId) = idToAddressAndId(id);
        IERC1155(token).safeTransferFrom(address(this), to, tokenId, amount, "");
        emit Burn(burner, to, id, amount);
    }

    function _burn(uint256 id, uint256 amount) internal {
        _supplies[id] -= amount;
    }

    // Balance
    function balanceOf(address account, uint256 id) public view returns (uint256) {
        return _balanceOf(account, id);
    }

    function balanceOfBatch(address[] calldata accounts, uint256[] calldata ids) public view returns (uint256[] memory) {
        uint256[] memory balances = new uint256[](accounts.length);
        for (uint256 i = 0; i < accounts.length; i++) {
            balances[i] = _balanceOf(accounts[i], ids[i]);
        }
        return balances;
    }

    function _balanceOf(address account, uint256 id) internal view returns (uint256) {
        return _balances[id][account];
    }

    function _lockedBalanceOf(address account, uint256 id) internal view returns (uint256) {
        return _lockedBalances[id][account];
    }

    function lockedBalanceOf(address account, uint256 id) public view returns (uint256) {
        return _lockedBalanceOf(account, id);
    }
    
    function _lockedBalanceOfBatch(address[] calldata accounts, uint256[] calldata ids) internal view returns (uint256[] memory) {
        uint256[] memory balances = new uint256[](accounts.length);
        for (uint256 i = 0; i < accounts.length; i++) {
            balances[i] = lockedBalanceOf(accounts[i], ids[i]);
        }
        return balances;
    }

    function _unlockedBalanceOf(address account, uint256 id) internal view returns (uint256) {
        return _balanceOf(account, id) - _lockedBalanceOf(account, id);
    }

    function unlockedBalanceOf(address account, uint256 id) public view returns (uint256) {
        return _unlockedBalanceOf(account, id);
    }

    function unlockedBalanceOfBatch(address[] calldata accounts, uint256[] calldata ids) public view returns (uint256[] memory) {
        uint256[] memory balances = new uint256[](accounts.length);
        for (uint256 i = 0; i < accounts.length; i++) {
            balances[i] = _unlockedBalanceOf(accounts[i], ids[i]);
        }
        return balances;
    }

    function _lockedBalanceByLocker(address account, uint256 id, address locker) internal view returns (uint256) {
        return _lockedBalancesByLocker[id][account][locker];
    }

    function lockedBalanceByLocker(address account, uint256 id, address locker) public view returns (uint256) {
        return _lockedBalanceByLocker(account, id, locker);
    }

    // Lock limit and expiration
    function _lockLimitOf(address account, uint256 id, address locker) internal view returns (uint256) {
        return _approvedLockLimitsByLocker[id][account][locker];
    }

    function lockLimitOf(address account, uint256 id, address locker) public view returns (uint256) {
        return _lockLimitOf(account, id, locker);
    }

    function _lockExpirationOf(address account, uint256 id, address locker) internal view returns (uint256) {
        return _approvedLockExpirationsByLocker[id][account][locker];
    }

    function lockExpirationOf(address account, uint256 id, address locker) public view returns (uint256) {
        return _lockExpirationOf(account, id, locker);
    }

    // Allowance
    function _allowanceOf(address account, uint256 id, address spender) internal view returns (uint256) {   
        return _approvedBalancesBySpender[id][account][spender];
    }

    function allowanceOf(address account, uint256 id, address spender) public view returns (uint256) {
        return _allowanceOf(account, id, spender);
    }

    // Supply
    function totalSupply(uint256 id) public view returns (uint256) {
        return _supplies[id];
    }

    function totalSupplyERC20(address token) public view returns (uint256) {
        return _supplies[addressToId(token)];
    }

    function totalSupplyERC721(address token, uint96 id) public view returns (uint256) {
        return _supplies[addressAndIdToId(token, id)];
    }

    function totalSupplyERC1155(address token, uint96 id) public view returns (uint256) {
        return _supplies[addressAndIdToId(token, id)];
    }
}
