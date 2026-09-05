// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Minimal example for SlotWarner single-contract early-warning analysis.
contract SingleWarning {
    address public owner;
    uint256 private withdrawalLimit;

    constructor() {
        owner = msg.sender;
    }

    // Intentionally left unrestricted for the early-warning example:
    // external input can directly influence persistent storage.
    function setWithdrawalLimit(uint256 newLimit) external {
        withdrawalLimit = newLimit;
    }

    function getWithdrawalLimit() external view returns (uint256) {
        return withdrawalLimit;
    }
}
