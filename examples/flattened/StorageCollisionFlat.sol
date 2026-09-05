// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Proxy and logic contracts intentionally kept in one flattened source file.
contract DemoProxy {
    // slot 0: 160 bits
    address public admin;
    // slot 1: 160 bits
    address public implementation;

    constructor(address impl) {
        admin = msg.sender;
        implementation = impl;
    }

    fallback() external payable {
        address impl = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch ok
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}

contract DemoLogic {
    // Both variables start in slot 0 and overlap DemoProxy.admin under DELEGATECALL.
    bool public initialized;
    address public operator;

    function initialize(address newOperator) external {
        initialized = true;
        operator = newOperator;
    }
}
