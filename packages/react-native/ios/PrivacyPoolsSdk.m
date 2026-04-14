#import <React/RCTBridgeModule.h>

@interface RCT_EXTERN_MODULE(PrivacyPoolsSdk, NSObject)

RCT_EXTERN_METHOD(getVersion:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(getStableBackendName:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(fastBackendSupportedOnTarget:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(deriveMasterKeys:(NSString *)mnemonic
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(deriveDepositSecrets:(NSString *)masterNullifier
                  masterSecret:(NSString *)masterSecret
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

RCT_EXTERN_METHOD(getCommitment:(NSString *)value
                  label:(NSString *)label
                  nullifier:(NSString *)nullifier
                  secret:(NSString *)secret
                  resolver:(RCTPromiseResolveBlock)resolve
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

RCT_EXTERN_METHOD(getArtifactStatuses:(NSString *)manifestJson
                  artifactsRoot:(NSString *)artifactsRoot
                  circuit:(NSString *)circuit
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(checkpointRecovery:(NSArray<NSDictionary *> *)events
                  policy:(NSDictionary *)policy
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

@end
