#import <React/RCTBridgeModule.h>

@interface RCT_EXTERN_REMAP_MODULE(PrivacyPoolsSdk, PrivacyPoolsSdkModule, NSObject)

RCT_EXTERN_METHOD(getVersion:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(getStableBackendName:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(deriveMasterKeys:(NSString *)mnemonic
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(deriveMasterKeysHandle:(NSString *)mnemonic
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(dangerouslyExportMasterKeys:(NSString *)handle
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(deriveDepositSecrets:(NSString *)masterNullifier
                  masterSecret:(NSString *)masterSecret
                  scope:(NSString *)scope
                  index:(NSString *)index
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(generateDepositSecretsHandle:(NSString *)masterKeysHandle
                  scope:(NSString *)scope
                  index:(NSString *)index
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(deriveWithdrawalSecrets:(NSString *)masterNullifier
                  masterSecret:(NSString *)masterSecret
                  label:(NSString *)label
                  index:(NSString *)index
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(generateWithdrawalSecretsHandle:(NSString *)masterKeysHandle
                  label:(NSString *)label
                  index:(NSString *)index
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(dangerouslyExportSecret:(NSString *)handle
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(getCommitment:(NSString *)value
                  label:(NSString *)label
                  nullifier:(NSString *)nullifier
                  secret:(NSString *)secret
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(getCommitmentFromHandles:(NSString *)value
                  label:(NSString *)label
                  secretsHandle:(NSString *)secretsHandle
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(dangerouslyExportCommitmentPreimage:(NSString *)handle
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(buildWithdrawalWitnessRequestHandle:(NSDictionary *)request
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(removeSecretHandle:(NSString *)handle
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(clearSecretHandles:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(removeVerifiedProofHandle:(NSString *)handle
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(clearVerifiedProofHandles:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(calculateWithdrawalContext:(NSDictionary *)withdrawal
                  scope:(NSString *)scope
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(generateMerkleProof:(NSArray<NSString *> *)leaves
                  leaf:(NSString *)leaf
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(buildCircuitMerkleWitness:(NSDictionary *)proof
                  depth:(nonnull NSNumber *)depth
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(buildWithdrawalCircuitInput:(NSDictionary *)request
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(buildCommitmentCircuitInput:(NSDictionary *)request
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(prepareWithdrawalCircuitSession:(NSString *)manifestJson
                  artifactsRoot:(NSString *)artifactsRoot
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(prepareWithdrawalCircuitSessionFromBytes:(NSString *)manifestJson
                  artifacts:(NSArray<NSDictionary *> *)artifacts
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(removeWithdrawalCircuitSession:(NSString *)handle
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(prepareCommitmentCircuitSession:(NSString *)manifestJson
                  artifactsRoot:(NSString *)artifactsRoot
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(prepareCommitmentCircuitSessionFromBytes:(NSString *)manifestJson
                  artifacts:(NSArray<NSDictionary *> *)artifacts
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(removeCommitmentCircuitSession:(NSString *)handle
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(proveWithdrawal:(NSString *)backendProfile
                  manifestJson:(NSString *)manifestJson
                  artifactsRoot:(NSString *)artifactsRoot
                  request:(NSDictionary *)request
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(proveWithdrawalWithSession:(NSString *)backendProfile
                  sessionHandle:(NSString *)sessionHandle
                  request:(NSDictionary *)request
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(proveWithdrawalWithHandles:(NSString *)backendProfile
                  manifestJson:(NSString *)manifestJson
                  artifactsRoot:(NSString *)artifactsRoot
                  requestHandle:(NSString *)requestHandle
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(proveCommitment:(NSString *)backendProfile
                  manifestJson:(NSString *)manifestJson
                  artifactsRoot:(NSString *)artifactsRoot
                  request:(NSDictionary *)request
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(proveCommitmentWithSession:(NSString *)backendProfile
                  sessionHandle:(NSString *)sessionHandle
                  request:(NSDictionary *)request
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(proveCommitmentWithHandle:(NSString *)backendProfile
                  manifestJson:(NSString *)manifestJson
                  artifactsRoot:(NSString *)artifactsRoot
                  requestHandle:(NSString *)requestHandle
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(startProveWithdrawalJob:(NSString *)backendProfile
                  manifestJson:(NSString *)manifestJson
                  artifactsRoot:(NSString *)artifactsRoot
                  request:(NSDictionary *)request
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(startProveWithdrawalJobWithSession:(NSString *)backendProfile
                  sessionHandle:(NSString *)sessionHandle
                  request:(NSDictionary *)request
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(verifyWithdrawalProof:(NSString *)backendProfile
                  manifestJson:(NSString *)manifestJson
                  artifactsRoot:(NSString *)artifactsRoot
                  proof:(NSDictionary *)proof
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(verifyWithdrawalProofWithSession:(NSString *)backendProfile
                  sessionHandle:(NSString *)sessionHandle
                  proof:(NSDictionary *)proof
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(verifyCommitmentProof:(NSString *)backendProfile
                  manifestJson:(NSString *)manifestJson
                  artifactsRoot:(NSString *)artifactsRoot
                  proof:(NSDictionary *)proof
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(verifyCommitmentProofWithSession:(NSString *)backendProfile
                  sessionHandle:(NSString *)sessionHandle
                  proof:(NSDictionary *)proof
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(proveAndVerifyCommitmentHandle:(NSString *)backendProfile
                  manifestJson:(NSString *)manifestJson
                  artifactsRoot:(NSString *)artifactsRoot
                  requestHandle:(NSString *)requestHandle
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(proveAndVerifyWithdrawalHandle:(NSString *)backendProfile
                  manifestJson:(NSString *)manifestJson
                  artifactsRoot:(NSString *)artifactsRoot
                  requestHandle:(NSString *)requestHandle
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(verifyCommitmentProofForRequestHandle:(NSString *)backendProfile
                  manifestJson:(NSString *)manifestJson
                  artifactsRoot:(NSString *)artifactsRoot
                  requestHandle:(NSString *)requestHandle
                  proof:(NSDictionary *)proof
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(verifyRagequitProofForRequestHandle:(NSString *)backendProfile
                  manifestJson:(NSString *)manifestJson
                  artifactsRoot:(NSString *)artifactsRoot
                  requestHandle:(NSString *)requestHandle
                  proof:(NSDictionary *)proof
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(verifyWithdrawalProofForRequestHandle:(NSString *)backendProfile
                  manifestJson:(NSString *)manifestJson
                  artifactsRoot:(NSString *)artifactsRoot
                  requestHandle:(NSString *)requestHandle
                  proof:(NSDictionary *)proof
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(pollJobStatus:(NSString *)jobId
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(getProveWithdrawalJobResult:(NSString *)jobId
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(cancelJob:(NSString *)jobId
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(removeJob:(NSString *)jobId
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(prepareWithdrawalExecution:(NSString *)backendProfile
                  manifestJson:(NSString *)manifestJson
                  artifactsRoot:(NSString *)artifactsRoot
                  request:(NSDictionary *)request
                  chainId:(nonnull NSNumber *)chainId
                  poolAddress:(NSString *)poolAddress
                  rpcUrl:(NSString *)rpcUrl
                  policy:(NSDictionary *)policy
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(startPrepareWithdrawalExecutionJob:(NSString *)backendProfile
                  manifestJson:(NSString *)manifestJson
                  artifactsRoot:(NSString *)artifactsRoot
                  request:(NSDictionary *)request
                  chainId:(nonnull NSNumber *)chainId
                  poolAddress:(NSString *)poolAddress
                  rpcUrl:(NSString *)rpcUrl
                  policy:(NSDictionary *)policy
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(getPrepareWithdrawalExecutionJobResult:(NSString *)jobId
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(prepareRelayExecution:(NSString *)backendProfile
                  manifestJson:(NSString *)manifestJson
                  artifactsRoot:(NSString *)artifactsRoot
                  request:(NSDictionary *)request
                  chainId:(nonnull NSNumber *)chainId
                  entrypointAddress:(NSString *)entrypointAddress
                  poolAddress:(NSString *)poolAddress
                  rpcUrl:(NSString *)rpcUrl
                  policy:(NSDictionary *)policy
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(startPrepareRelayExecutionJob:(NSString *)backendProfile
                  manifestJson:(NSString *)manifestJson
                  artifactsRoot:(NSString *)artifactsRoot
                  request:(NSDictionary *)request
                  chainId:(nonnull NSNumber *)chainId
                  entrypointAddress:(NSString *)entrypointAddress
                  poolAddress:(NSString *)poolAddress
                  rpcUrl:(NSString *)rpcUrl
                  policy:(NSDictionary *)policy
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(getPrepareRelayExecutionJobResult:(NSString *)jobId
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(registerHostProvidedSigner:(NSString *)handle
                  address:(NSString *)address
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(registerMobileSecureStorageSigner:(NSString *)handle
                  address:(NSString *)address
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(unregisterSigner:(NSString *)handle
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(finalizePreparedTransaction:(NSString *)rpcUrl
                  prepared:(NSDictionary *)prepared
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(finalizePreparedTransactionForSigner:(NSString *)rpcUrl
                  signerHandle:(NSString *)signerHandle
                  prepared:(NSDictionary *)prepared
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(submitPreparedTransaction:(NSString *)rpcUrl
                  signerHandle:(NSString *)signerHandle
                  prepared:(NSDictionary *)prepared
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(submitSignedTransaction:(NSString *)rpcUrl
                  finalized:(NSDictionary *)finalized
                  signedTransaction:(NSString *)signedTransaction
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(planWithdrawalTransaction:(nonnull NSNumber *)chainId
                  poolAddress:(NSString *)poolAddress
                  withdrawal:(NSDictionary *)withdrawal
                  proof:(NSDictionary *)proof
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(planRelayTransaction:(nonnull NSNumber *)chainId
                  entrypointAddress:(NSString *)entrypointAddress
                  withdrawal:(NSDictionary *)withdrawal
                  proof:(NSDictionary *)proof
                  scope:(NSString *)scope
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(planRagequitTransaction:(nonnull NSNumber *)chainId
                  poolAddress:(NSString *)poolAddress
                  proof:(NSDictionary *)proof
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(planVerifiedWithdrawalTransactionWithHandle:(nonnull NSNumber *)chainId
                  poolAddress:(NSString *)poolAddress
                  proofHandle:(NSString *)proofHandle
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(planVerifiedRelayTransactionWithHandle:(nonnull NSNumber *)chainId
                  entrypointAddress:(NSString *)entrypointAddress
                  proofHandle:(NSString *)proofHandle
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(planVerifiedRagequitTransactionWithHandle:(nonnull NSNumber *)chainId
                  poolAddress:(NSString *)poolAddress
                  proofHandle:(NSString *)proofHandle
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(planPoolStateRootRead:(NSString *)poolAddress
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(planAspRootRead:(NSString *)entrypointAddress
                  poolAddress:(NSString *)poolAddress
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(isCurrentStateRoot:(NSString *)expectedRoot
                  currentRoot:(NSString *)currentRoot
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(formatGroth16ProofBundle:(NSDictionary *)proof
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(verifyArtifactBytes:(NSString *)manifestJson
	                  circuit:(NSString *)circuit
	                  kind:(NSString *)kind
	                  bytes:(NSArray<NSNumber *> *)bytes
	                  resolver:(RCTPromiseResolveBlock)resolve
	                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(verifySignedManifest:(NSString *)payloadJson
                  signatureHex:(NSString *)signatureHex
                  publicKeyHex:(NSString *)publicKeyHex
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(verifySignedManifestArtifacts:(NSString *)payloadJson
                  signatureHex:(NSString *)signatureHex
                  publicKeyHex:(NSString *)publicKeyHex
                  artifacts:(NSArray<NSDictionary *> *)artifacts
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(getArtifactStatuses:(NSString *)manifestJson
                  artifactsRoot:(NSString *)artifactsRoot
                  circuit:(NSString *)circuit
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(resolveVerifiedArtifactBundle:(NSString *)manifestJson
                  artifactsRoot:(NSString *)artifactsRoot
                  circuit:(NSString *)circuit
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(checkpointRecovery:(NSArray<NSDictionary *> *)events
                  policy:(NSDictionary *)policy
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

@end
