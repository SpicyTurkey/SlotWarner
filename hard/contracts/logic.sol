// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract LogicV1 {
    // 重要：存储变量的顺序和类型必须与代理合约匹配
    address public implementation;
    address public admin;
    
    // 业务逻辑的状态变量
    uint256 public value;
    string public text;
    address public owner;
    
    // 初始化函数（代替构造函数）
    function initialize() public {
        require(owner == address(0), "Already initialized");
        owner = msg.sender;
        value = 100;
        text = "Version 1";
    }
    
    // 业务逻辑函数
    function setValue(uint256 _value) public {
        value = _value;
    }
    
    function setText(string memory _text) public {
        text = _text;
    }
    
    function getData() public view returns (uint256, string memory) {
        return (value, text);
    }
    
    // 版本标识
    function version() public pure returns (string memory) {
        return "V1";
    }
}

pragma solidity ^0.8.0;

contract Proxy {
    // 存储槽0：逻辑合约地址
    address public implementation;
    // 存储槽1：管理员地址
    address public admin;
    address public owner;
    
    // 注意：不要在这里添加其他状态变量，避免存储冲突
    
    constructor(address _implementation) {
        admin = msg.sender;
        implementation = _implementation;
    }
    
    // 升级函数 - 只有管理员可以调用
    function upgrade(address newImplementation) public {
        require(msg.sender == admin, "Only admin");
        implementation = newImplementation;
    }
    
    // 回退函数 - 将所有调用委托给逻辑合约
    fallback() external payable {
        address _implementation = implementation;
        require(_implementation != address(0));
        
        // 委托调用逻辑合约
        assembly {
            // 复制calldata到内存
            calldatacopy(0, 0, calldatasize())
            
            // 委托调用逻辑合约
            let result := delegatecall(gas(), _implementation, 0, calldatasize(), 0, 0)
            
            // 复制returndata到内存
            returndatacopy(0, 0, returndatasize())
            
            // 处理返回结果
            switch result
            case 0 {
                revert(0, returndatasize())
            }
            default {
                return(0, returndatasize())
            }
        }
    }
    
    // 接收以太币
    receive() external payable {}
}
