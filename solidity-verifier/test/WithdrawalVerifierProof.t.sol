// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {WithdrawalVerifier} from "../src/WithdrawalVerifier.sol";

interface Vm {
  function readFileBinary(string calldata path) external view returns (bytes memory data);
}

contract WithdrawalVerifierProofTest {
  Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

  function testRustGeneratedWithdrawalProofAccepted() external {
    bytes memory encoded = vm.readFileBinary("fixtures/generated/withdrawal-proof.abi");
    (uint256[2] memory pA, uint256[2][2] memory pB, uint256[2] memory pC, uint256[8] memory pubSignals) =
      abi.decode(encoded, (uint256[2], uint256[2][2], uint256[2], uint256[8]));

    bool accepted = new WithdrawalVerifier().verifyProof(pA, pB, pC, pubSignals);
    require(accepted, "rust-generated withdrawal proof rejected by solidity verifier");
  }
}
