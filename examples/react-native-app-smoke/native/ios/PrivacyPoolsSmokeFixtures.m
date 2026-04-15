#import <React/RCTBridgeModule.h>

@interface RCT_EXTERN_MODULE(PrivacyPoolsSmokeFixtures, NSObject)

RCT_EXTERN_METHOD(copyFixtures:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(markSuccess:(NSString *)marker
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(markFailure:(NSString *)marker
                  message:(NSString *)message
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

@end
