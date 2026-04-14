Pod::Spec.new do |s|
  s.name = "PrivacyPoolsSdk"
  s.version = "0.1.0-alpha.1"
  s.summary = "React Native bridge for the Rust-first Privacy Pools SDK."
  s.description = <<-DESC
  Thin React Native bridge over the generated Swift bindings and Rust FFI artifacts
  for the Privacy Pools SDK.
  DESC
  s.homepage = "https://github.com/0xmatthewb/privacy-pools-sdk-rs"
  s.license = { :type => "Apache-2.0" }
  s.author = "0xbow"
  s.source = { :git => "https://github.com/0xmatthewb/privacy-pools-sdk-rs.git", :branch => "main" }
  s.swift_version = "5.10"
  s.ios.deployment_target = "15.0"

  s.prepare_command = "bash ../../bindings/ios/scripts/build-xcframework.sh"
  s.source_files = [
    "ios/**/*.{swift,m}",
    "../../bindings/ios/generated/PrivacyPoolsSdk.swift",
  ]
  s.dependency "React-Core"
  s.vendored_frameworks = "../../bindings/ios/build/PrivacyPoolsSdkFFI.xcframework"
end
