Pod::Spec.new do |s|
  s.name = "PrivacyPoolsSdk"
  s.version = "0.1.0-alpha.1"
  s.summary = "Privacy Pools SDK for iOS."
  s.description = <<-DESC
  Generated Swift bindings and packaged native artifacts for the Privacy Pools SDK.
  DESC
  s.homepage = "https://github.com/0xmatthewb/privacy-pools-sdk-rs"
  s.license = { :type => "Apache-2.0" }
  s.author = "0xbow"
  s.source = { :git => "https://github.com/0xmatthewb/privacy-pools-sdk-rs.git", :branch => "main" }
  s.swift_version = "5.10"
  s.ios.deployment_target = "15.0"

  s.prepare_command = "bash scripts/build-xcframework.sh"
  s.source_files = [
    "generated/PrivacyPoolsSdk.swift",
    "Sources/PrivacyPoolsSdk/**/*.swift",
  ]
  s.preserve_paths = [
    "generated/PrivacyPoolsSdkFFI.h",
    "generated/PrivacyPoolsSdkFFI.modulemap",
    "build/PrivacyPoolsSdkFFI.xcframework",
  ]
  s.vendored_frameworks = "build/PrivacyPoolsSdkFFI.xcframework"
end
