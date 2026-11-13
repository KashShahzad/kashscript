// KashWalletRootModule.swift
//
// The wallet's hardware root on iOS, and its blob store.
//
// The root is a P-256 key made in the Secure Enclave with CryptoKit's
// SecureEnclave.P256.KeyAgreement type. That type has no signing operation, so
// the root cannot sign a record — by construction (ECOSYSTEM d47(g)(1)). It is
// used only through `agree`, which the Secure Enclave allows only after the
// person's face, fingerprint or passcode (.userPresence). The key's opaque
// blob (usable only by this phone's Secure Enclave) is kept in the Keychain as
// WhenPasscodeSetThisDeviceOnly: never in a backup, never on another device.
//
// The blob store keeps the wallet's sealed files in Application Support, with
// complete file protection, excluded from iCloud backups — so nothing the
// wallet keeps, the switch included, syncs anywhere.
//
// Written against CryptoKit and ExpoModulesCore; compiled in an app's
// development build (PL-9), not in this repository.

import ExpoModulesCore
import CryptoKit
import Foundation
import LocalAuthentication
import Security

public class KashWalletRootModule: Module {
  private static let service = "kashscript.wallet.root"
  private static let storeDirName = "kash-wallet"

  public func definition() -> ModuleDefinition {
    Name("KashWalletRoot")

    AsyncFunction("isAvailable") { (promise: Promise) in
      if !SecureEnclave.isAvailable {
        promise.resolve(["available": false, "reason": "no-secure-hardware"])
        return
      }
      var error: NSError?
      if !LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) {
        promise.resolve(["available": false, "reason": "no-screen-lock"])
        return
      }
      promise.resolve(["available": true, "reason": NSNull()])
    }

    AsyncFunction("create") { (alias: String, promise: Promise) in
      do {
        if try Self.loadKeyBlob(alias) != nil {
          promise.reject("E_EXISTS", "a root already exists")
          return
        }
        var cfError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
          nil,
          kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
          [.privateKeyUsage, .userPresence],
          &cfError
        ) else {
          promise.reject("E_ACCESS", "could not make the access control")
          return
        }
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(compactRepresentable: false, accessControl: access)
        try Self.saveKeyBlob(alias, key.dataRepresentation)
        promise.resolve(Self.base64url(key.publicKey.x963Representation))
      } catch {
        promise.reject("E_CREATE", error.localizedDescription)
      }
    }

    AsyncFunction("publicKey") { (alias: String, promise: Promise) in
      do {
        guard let blob = try Self.loadKeyBlob(alias) else {
          promise.resolve(NSNull())
          return
        }
        // Reading the public half uses no private-key operation, so no prompt.
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blob)
        promise.resolve(Self.base64url(key.publicKey.x963Representation))
      } catch {
        promise.reject("E_PUBLIC_KEY", error.localizedDescription)
      }
    }

    AsyncFunction("where") { (alias: String, promise: Promise) in
      do {
        promise.resolve(try Self.loadKeyBlob(alias) == nil ? NSNull() : "secure-enclave")
      } catch {
        promise.reject("E_WHERE", error.localizedDescription)
      }
    }

    AsyncFunction("agree") { (alias: String, peer: String, prompt: String, promise: Promise) in
      do {
        guard let blob = try Self.loadKeyBlob(alias) else {
          promise.reject("E_NO_ROOT", "no root on this phone")
          return
        }
        guard let peerBytes = Self.base64urlDecode(peer), peerBytes.count == 65, peerBytes.first == 0x04 else {
          promise.reject("E_BAD_PEER", "the peer key is not an uncompressed P-256 key")
          return
        }
        let context = LAContext()
        context.localizedReason = prompt
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blob, authenticationContext: context)
        let peerKey = try P256.KeyAgreement.PublicKey(x963Representation: peerBytes)
        let shared = try key.sharedSecretFromKeyAgreement(with: peerKey)
        promise.resolve(shared.withUnsafeBytes { Self.base64url(Data($0)) })
      } catch {
        promise.reject("E_AGREE", error.localizedDescription)
      }
    }

    // ── signing keys (PL-2) ─────────────────────────────────────────────
    // Separate keys — one per place, one per copy of a yes — of CryptoKit's
    // SecureEnclave.P256.Signing type, never the root (a KeyAgreement key, which
    // cannot sign). ES256: `signature(for:)` hashes with SHA-256 inside the
    // Secure Enclave, after the face, fingerprint or passcode. DER comes back;
    // the wallet makes it low-S. Blobs are Keychain items like the root's:
    // WhenPasscodeSetThisDeviceOnly, never in a backup, never on another device.

    AsyncFunction("createSigningKey") { (alias: String, promise: Promise) in
      do {
        if try Self.loadKeyBlob(alias) != nil {
          promise.reject("E_EXISTS", "a key with this name exists")
          return
        }
        var cfError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
          nil,
          kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
          [.privateKeyUsage, .userPresence],
          &cfError
        ) else {
          promise.reject("E_ACCESS", "could not make the access control")
          return
        }
        let key = try SecureEnclave.P256.Signing.PrivateKey(compactRepresentable: false, accessControl: access)
        try Self.saveKeyBlob(alias, key.dataRepresentation)
        promise.resolve(["publicKey": Self.base64url(key.publicKey.x963Representation), "where": "secure-enclave"])
      } catch {
        promise.reject("E_CREATE_SIGNING", error.localizedDescription)
      }
    }

    AsyncFunction("signWithKey") { (alias: String, message: String, prompt: String, promise: Promise) in
      do {
        guard let blob = try Self.loadKeyBlob(alias) else {
          promise.reject("E_NO_KEY", "no such signing key on this phone")
          return
        }
        guard let data = Self.base64urlDecode(message) else {
          promise.reject("E_BAD_MESSAGE", "the message is not base64url")
          return
        }
        let context = LAContext()
        context.localizedReason = prompt
        let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob, authenticationContext: context)
        let signature = try key.signature(for: data)
        promise.resolve(Self.base64url(signature.derRepresentation))
      } catch {
        promise.reject("E_SIGN", error.localizedDescription)
      }
    }

    AsyncFunction("removeSigningKey") { (alias: String, promise: Promise) in
      promise.resolve(Self.deleteKeyBlob(alias))
    }

    AsyncFunction("remove") { (alias: String, promise: Promise) in
      promise.resolve(Self.deleteKeyBlob(alias))
    }

    AsyncFunction("blobPut") { (name: String, base64: String, promise: Promise) in
      do {
        guard let data = Data(base64Encoded: base64) else {
          promise.reject("E_BAD_BLOB", "not base64")
          return
        }
        try data.write(to: try Self.file(name), options: [.atomic, .completeFileProtection])
        promise.resolve(nil)
      } catch {
        promise.reject("E_BLOB_PUT", error.localizedDescription)
      }
    }

    AsyncFunction("blobGet") { (name: String, promise: Promise) in
      do {
        let url = try Self.file(name)
        guard FileManager.default.fileExists(atPath: url.path) else {
          promise.resolve(NSNull())
          return
        }
        promise.resolve(try Data(contentsOf: url).base64EncodedString())
      } catch {
        promise.reject("E_BLOB_GET", error.localizedDescription)
      }
    }

    AsyncFunction("blobDelete") { (name: String, promise: Promise) in
      do {
        let url = try Self.file(name)
        if FileManager.default.fileExists(atPath: url.path) {
          try FileManager.default.removeItem(at: url)
        }
        promise.resolve(nil)
      } catch {
        promise.reject("E_BLOB_DELETE", error.localizedDescription)
      }
    }

    AsyncFunction("blobList") { (prefix: String, promise: Promise) in
      do {
        let names = try FileManager.default.contentsOfDirectory(atPath: try Self.storeDir().path)
        promise.resolve(names.filter { $0.hasPrefix(prefix) })
      } catch {
        promise.reject("E_BLOB_LIST", error.localizedDescription)
      }
    }
  }

  // MARK: - The key blob, in the Keychain, this device only

  private static func keyQuery(_ alias: String) -> [String: Any] {
    return [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: alias,
    ]
  }

  private static func saveKeyBlob(_ alias: String, _ data: Data) throws {
    var query = keyQuery(alias)
    query[kSecValueData as String] = data
    query[kSecAttrAccessible as String] = kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
    let status = SecItemAdd(query as CFDictionary, nil)
    guard status == errSecSuccess else {
      throw NSError(domain: "KashWalletRoot", code: Int(status), userInfo: [NSLocalizedDescriptionKey: "keychain add failed (\(status))"])
    }
  }

  private static func loadKeyBlob(_ alias: String) throws -> Data? {
    var query = keyQuery(alias)
    query[kSecReturnData as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitOne
    var out: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &out)
    if status == errSecItemNotFound { return nil }
    guard status == errSecSuccess else {
      throw NSError(domain: "KashWalletRoot", code: Int(status), userInfo: [NSLocalizedDescriptionKey: "keychain read failed (\(status))"])
    }
    return out as? Data
  }

  private static func deleteKeyBlob(_ alias: String) -> Bool {
    return SecItemDelete(keyQuery(alias) as CFDictionary) == errSecSuccess
  }

  // MARK: - The blob store: private, protected, out of backups

  private static func storeDir() throws -> URL {
    let base = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
    var dir = base.appendingPathComponent(storeDirName, isDirectory: true)
    if !FileManager.default.fileExists(atPath: dir.path) {
      try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.protectionKey: FileProtectionType.complete])
    }
    var values = URLResourceValues()
    values.isExcludedFromBackup = true
    try dir.setResourceValues(values)
    return dir
  }

  private static func file(_ name: String) throws -> URL {
    guard !name.isEmpty, name.range(of: "^[a-z0-9.]+$", options: .regularExpression) != nil else {
      throw NSError(domain: "KashWalletRoot", code: 1, userInfo: [NSLocalizedDescriptionKey: "bad blob name"])
    }
    return try storeDir().appendingPathComponent(name, isDirectory: false)
  }

  // MARK: - base64url

  private static func base64url(_ data: Data) -> String {
    return data.base64EncodedString()
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
  }

  private static func base64urlDecode(_ s: String) -> Data? {
    var b64 = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
    while b64.count % 4 != 0 { b64 += "=" }
    return Data(base64Encoded: b64)
  }
}
