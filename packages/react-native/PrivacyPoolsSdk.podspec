Pod::Spec.new do |s|
  s.name = "PrivacyPoolsSdk"
  s.version = "0.1.0-alpha.1"
  s.summary = "React Native bridge for the Privacy Pools SDK."
  s.description = <<-DESC
  React Native bridge over the generated Swift bindings and packaged native artifacts
  for the Privacy Pools SDK.
  DESC
  s.homepage = "https://github.com/0xmatthewb/privacy-pools-sdk-rs"
  s.license = { :type => "Apache-2.0" }
  s.author = "0xbow"
  s.source = { :git => "https://github.com/0xmatthewb/privacy-pools-sdk-rs.git", :branch => "main" }
  s.swift_version = "5.10"
  s.ios.deployment_target = "15.0"

  s.source_files = [
    "ios/*.{swift,m,h}",
    "ios/generated/**/*.{swift,h}",
  ]
  s.public_header_files = [
    "ios/generated/PrivacyPoolsSdkFFI.h",
  ]
  s.preserve_paths = [
    "ios/generated/PrivacyPoolsSdkFFI.h",
    "ios/generated/PrivacyPoolsSdkFFI.modulemap",
    "ios/frameworks/PrivacyPoolsSdkFFI.xcframework",
  ]
  s.dependency "React-Core"
  s.vendored_frameworks = "ios/frameworks/PrivacyPoolsSdkFFI.xcframework"
end
