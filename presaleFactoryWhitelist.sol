/**
 *Submitted for verification at BscScan.com on 2022-01-23
*/

// File: @openzeppelin/contracts/security/ReentrancyGuard.sol


// OpenZeppelin Contracts v4.4.1 (security/ReentrancyGuard.sol)

pragma solidity ^0.8.0;

/**
 * @dev Contract module that helps prevent reentrant calls to a function.
 *
 * Inheriting from `ReentrancyGuard` will make the {nonReentrant} modifier
 * available, which can be applied to functions to make sure there are no nested
 * (reentrant) calls to them.
 *
 * Note that because there is a single `nonReentrant` guard, functions marked as
 * `nonReentrant` may not call one another. This can be worked around by making
 * those functions `private`, and then adding `external` `nonReentrant` entry
 * points to them.
 *
 * TIP: If you would like to learn more about reentrancy and alternative ways
 * to protect against it, check out our blog post
 * https://blog.openzeppelin.com/reentrancy-after-istanbul/[Reentrancy After Istanbul].
 */
abstract contract ReentrancyGuard {
    // Booleans are more expensive than uint256 or any type that takes up a full
    // word because each write operation emits an extra SLOAD to first read the
    // slot's contents, replace the bits taken up by the boolean, and then write
    // back. This is the compiler's defense against contract upgrades and
    // pointer aliasing, and it cannot be disabled.

    // The values being non-zero value makes deployment a bit more expensive,
    // but in exchange the refund on every call to nonReentrant will be lower in
    // amount. Since refunds are capped to a percentage of the total
    // transaction's gas, it is best to keep them low in cases like this one, to
    // increase the likelihood of the full refund coming into effect.
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;

    uint256 private _status;

    constructor() {
        _status = _NOT_ENTERED;
    }

    /**
     * @dev Prevents a contract from calling itself, directly or indirectly.
     * Calling a `nonReentrant` function from another `nonReentrant`
     * function is not supported. It is possible to prevent this from happening
     * by making the `nonReentrant` function external, and making it call a
     * `private` function that does the actual work.
     */
    modifier nonReentrant() {
        // On the first call to nonReentrant, _notEntered will be true
        require(_status != _ENTERED, "ReentrancyGuard: reentrant call");

        // Any calls to nonReentrant after this point will fail
        _status = _ENTERED;

        _;

        // By storing the original value once again, a refund is triggered (see
        // https://eips.ethereum.org/EIPS/eip-2200)
        _status = _NOT_ENTERED;
    }
}


// File: contracts/Presale.sol

/**
 *Submitted for verification at BscScan.com on 2021-11-16
*/

/**
 *Submitted for verification at BscScan.com on 2021-11-03
*/

pragma solidity ^0.8.0;

/**
 * @dev Interface of the ERC20 standard as defined in the EIP. Does not include
 * the optional functions; to access them see `ERC20Detailed`.
 */

interface IERC20 {
    function totalSupply() external view returns (uint256);

    function balanceOf(address account) external view returns (uint256);

    function transfer(address recipient, uint256 amount)
        external
        returns (bool);

    function allowance(address owner, address spender)
        external
        view
        returns (uint256);

    function approve(address spender, uint256 amount) external returns (bool);

    function transferFrom(
        address sender,
        address recipient,
        uint256 amount
    ) external returns (bool);

    event Transfer(address indexed from, address indexed to, uint256 value);

    event Approval(
        address indexed owner,
        address indexed spender,
        uint256 value
    );
}


library SafeMath {
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        require(c >= a, "SafeMath: addition overflow");

        return c;
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b <= a, "SafeMath: subtraction overflow");
        uint256 c = a - b;

        return c;
    }

    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0) {
            return 0;
        }

        uint256 c = a * b;
        require(c / a == b, "SafeMath: multiplication overflow");

        return c;
    }

    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        // Solidity only automatically asserts when dividing by 0
        require(b > 0, "SafeMath: division by zero");
        uint256 c = a / b;
        // assert(a == b * c + a % b); // There is no case in which this doesn't hold
        return c;
    }

    function mod(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b != 0, "SafeMath: modulo by zero");
        return a % b;
    }
}


abstract contract Context {
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }

    function _msgData() internal view virtual returns (bytes calldata) {
        return msg.data;
    }
}


abstract contract Ownable is Context {
    address private _owner;

    event OwnershipTransferred(
        address indexed previousOwner,
        address indexed newOwner
    );

    constructor() {
        _transferOwnership(_msgSender());
    }

    function owner() public view virtual returns (address) {
        return _owner;
    }

    modifier onlyOwner() {
        require(owner() == _msgSender(), "Ownable: caller is not the owner");
        _;
    }

    function renounceOwnership() public virtual onlyOwner {
        _transferOwnership(address(0));
    }

    function transferOwnership(address newOwner) public virtual onlyOwner {
        require(
            newOwner != address(0),
            "Ownable: new owner is the zero address"
        );
        _transferOwnership(newOwner);
    }

    function _transferOwnership(address newOwner) internal virtual {
        address oldOwner = _owner;
        _owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }
}

library SafeERC20 {
    function safeTransfer(
        IERC20 token,
        address to,
        uint256 value
    ) internal {
        require(token.transfer(to, value));
    }

    function safeTransferFrom(
        IERC20 token,
        address from,
        address to,
        uint256 value
    ) internal {
        require(token.transferFrom(from, to, value));
    }

    function safeApprove(
        IERC20 token,
        address spender,
        uint256 value
    ) internal {
        require(token.approve(spender, value));
    }
}

abstract contract Pausable is Context {
    event Paused(address account);

    event Unpaused(address account);

    bool private _paused;

    constructor() {
        _paused = false;
    }

    function paused() public view virtual returns (bool) {
        return _paused;
    }

    modifier whenNotPaused() {
        require(!paused(), "Pausable: paused");
        _;
    }

    modifier whenPaused() {
        require(paused(), "Pausable: not paused");
        _;
    }

    function _pause() internal virtual whenNotPaused {
        _paused = true;
        emit Paused(_msgSender());
    }

    function _unpause() internal virtual whenPaused {
        _paused = false;
        emit Unpaused(_msgSender());
    }
}

contract StandardSale is Ownable, Pausable {
    using SafeMath for uint256;
    using SafeERC20 for IERC20;

    address public projectOwner;
    string public name;
    uint256 public maxCap;
    uint256 public saleStart;
    uint256 public saleEnd;
    address public tokenAddress;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
    uint256 public totalBalance;
    uint256 public transactions;   
    IERC20 public ERC20Interface;

    struct user {
        uint256 status;
        uint256 investedAmount;
    }

    mapping(address => user) public userDetails;

    constructor(
        address _projectOwner,
        string memory _name,
        string memory _symbol,
        uint256 _maxCap,
        uint256 _saleStart,
        uint256 _saleEnd, 
        uint8 _decimals, 
        uint256 _totalSupply,       
        address _tokenAddress
    ) {
        name = _name;
        symbol = _symbol;
        decimals = _decimals;
        totalSupply = _totalSupply;
        require(_maxCap > 0, "Zero max cap");
        maxCap = _maxCap;
        require(
            _saleStart > block.timestamp && _saleEnd > _saleStart,
            "Invalid timings"
        );
        saleStart = _saleStart;
        saleEnd = _saleEnd;
        require(_projectOwner != address(0), "Zero project owner address");
        projectOwner = _projectOwner;
        require(_tokenAddress != address(0), "Zero token address");
        tokenAddress = _tokenAddress;
        ERC20Interface = IERC20(tokenAddress);
       
    }

    function updateStartTime(uint256 newsaleStart) public onlyOwner {
        require(block.timestamp < saleStart, "Sale already started");
        saleStart = newsaleStart;
    }

    function updateEndTime(uint256 newSaleEnd) public onlyOwner {
        require(
            newSaleEnd > saleStart && newSaleEnd > block.timestamp,
            "Sale end can't be less than sale start"
        );
        saleEnd = newSaleEnd;
    }

    function pause() public onlyOwner {
        _pause();
    }

    function unpause() public onlyOwner {
        _unpause();
    }

    function whitelistUsers(address[] memory _users)
        external
        onlyOwner
    {
        require(_users.length > 0, "Empty Array");
        for (uint256 i = 0; i < _users.length; i++) {
            userDetails[_users[i]].status = 1;
        }
    }

    function buyTokens() public payable {
        require(userDetails[msg.sender].status == 1, "not whitelisted");
        require(block.timestamp >= saleStart, "Sale not started yet");
        require(block.timestamp <= saleEnd, "Sale Ended");
        require(
            totalBalance.add(msg.value) <= maxCap,
            "Exceeds launchpad max cap"
        );
        userDetails[msg.sender].investedAmount += msg.value;
        transactions++;
        totalBalance = totalBalance.add(msg.value);
    }


     function withdrawMoney() public {
        require(block.timestamp <= saleEnd, "Sale Ended");
        address payable to = payable(msg.sender);
        to.transfer(userDetails[msg.sender].investedAmount);
    }

    function claimToken(uint256 _presaleRate) external {
        require(block.timestamp >= saleEnd, "Sale not Ended yet");
        // transfer the token from address of this contract  
        uint256 noOfTokens = userDetails[msg.sender].investedAmount * _presaleRate;      
        ERC20Interface.transfer(msg.sender, noOfTokens);
    }

}
// File: contracts/PresaleFactory.sol


pragma solidity ^0.8.0;

contract PresaleFactory is Ownable, ReentrancyGuard{
    using SafeMath for uint256;
    address public feeTo;
    uint256 public flatFee;

    function refundExcessiveFee() internal {
    uint256 refund = msg.value.sub(flatFee);
    if (refund > 0) {
      payable(msg.sender).transfer(refund);
    }
  }

 modifier enoughFee() {
    require(msg.value >= flatFee, "Flat fee");
    _;
  }

  function setFeeTo(address feeReceivingAddress) external onlyOwner {
    feeTo = feeReceivingAddress;
  }

  function setFlatFee(uint256 fee) external onlyOwner {
    flatFee = fee;
  }

    function create(
    string memory name, 
    string memory symbol, 
    uint256 maxCap, 
    uint256 saleStart,
    uint256 saleEnd, 
    uint8 decimals, 
    uint256 totalSupply,
    address tokenAddress
  ) external payable enoughFee nonReentrant returns (address presaleAddress) {
    refundExcessiveFee();
    payable(feeTo).transfer(flatFee);
    presaleAddress = address(new StandardSale(
      msg.sender,
      name, 
      symbol,
      maxCap,
      saleStart,
      saleEnd,
      decimals,
      totalSupply,
      tokenAddress
    ));
    IERC20(tokenAddress).transferFrom(msg.sender, presaleAddress, 100000000000000000000);
    return presaleAddress;
    
  }
}