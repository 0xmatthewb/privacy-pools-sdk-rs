// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

struct WithdrawalAbiHarness {
    address processooor;
    bytes data;
}

struct WithdrawProofAbiHarness {
    uint256[2] pA;
    uint256[2][2] pB;
    uint256[2] pC;
    uint256[8] pubSignals;
}

contract MockEntrypointHarness {
    uint256 public latestRoot;

    function setLatestRoot(uint256 root) external {
        latestRoot = root;
    }

    function relay(
        WithdrawalAbiHarness calldata,
        WithdrawProofAbiHarness calldata,
        uint256
    ) external pure {}
}

contract MockPrivacyPoolHarness {
    address public ENTRYPOINT;
    uint256 public currentRoot;
    uint32 public currentRootIndex;
    mapping(uint256 => uint256) public roots;

    constructor(address entrypoint) {
        ENTRYPOINT = entrypoint;
    }

    function setEntrypoint(address entrypoint) external {
        ENTRYPOINT = entrypoint;
    }

    function setCurrentRoot(uint256 root, uint32 index) external {
        currentRoot = root;
        currentRootIndex = index;
        roots[index] = root;
    }

    function setHistoricalRoot(uint256 index, uint256 root) external {
        roots[index] = root;
    }

    function withdraw(
        WithdrawalAbiHarness calldata,
        WithdrawProofAbiHarness calldata
    ) external pure {}
}
