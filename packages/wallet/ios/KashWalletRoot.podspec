require 'json'

package = JSON.parse(File.read(File.join(__dir__, '..', 'package.json')))

Pod::Spec.new do |s|
  s.name           = 'KashWalletRoot'
  s.version        = package['version']
  s.summary        = 'The wallet component\'s hardware root (Secure Enclave, key agreement only) and blob store.'
  s.description    = package['description']
  s.license        = 'Apache-2.0'
  s.author         = 'KashScript'
  s.homepage       = 'https://www.kashscript.com'
  s.platforms      = { :ios => '15.1' }
  s.swift_version  = '5.4'
  s.source         = { git: '' }
  s.static_framework = true

  s.dependency 'ExpoModulesCore'

  s.frameworks = 'CryptoKit', 'LocalAuthentication', 'Security'

  s.pod_target_xcconfig = {
    'DEFINES_MODULE' => 'YES',
    'SWIFT_COMPILATION_MODE' => 'wholemodule'
  }

  s.source_files = "**/*.{h,m,mm,swift,hpp,cpp}"
end
