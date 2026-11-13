package expo.modules.kashwalletroot

import android.app.KeyguardManager
import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.annotation.RequiresApi
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import expo.modules.kotlin.Promise
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import java.io.File
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import javax.crypto.KeyAgreement

// The wallet's hardware root on Android, and its blob store.
//
// The root is a P-256 key whose ONLY purpose is key agreement (PURPOSE_AGREE_KEY),
// generated inside the Android Keystore — StrongBox where the phone has one, else
// the trusted environment. The Keystore refuses to sign with a key made for
// agreement, so the root cannot sign a record (ECOSYSTEM d47(g)(1)). It is usable
// only for a few seconds after the person's fingerprint, face or screen lock.
// PURPOSE_AGREE_KEY needs Android 12 (API 31); older phones are told plainly that
// they can't hold the root — never given a quieter, weaker key.
//
// The blob store keeps the wallet's sealed files in noBackupFilesDir, so nothing
// the wallet keeps, the switch included, reaches a cloud backup.
//
// Written against the Android Keystore and ExpoModulesCore; compiled in an app's
// development build (PL-9), not in this repository.
class KashWalletRootModule : Module() {
  companion object {
    private const val KEYSTORE = "AndroidKeyStore"
    private const val AUTH_WINDOW_SECONDS = 10
    private const val STORE_DIR = "kash-wallet"
    private val NAME = Regex("^[a-z0-9.]+$")
  }

  override fun definition() = ModuleDefinition {
    Name("KashWalletRoot")

    AsyncFunction("isAvailable") { availability() }

    AsyncFunction("create") { alias: String, promise: Promise -> create(alias, promise) }

    AsyncFunction("publicKey") { alias: String -> publicKeyOf(alias) }

    AsyncFunction("where") { alias: String -> whereOf(alias) }

    AsyncFunction("agree") { alias: String, peer: String, prompt: String, promise: Promise -> agree(alias, peer, prompt, promise) }

    AsyncFunction("remove") { alias: String -> remove(alias) }
    AsyncFunction("createSigningKey") { alias: String, promise: Promise -> createSigningKey(alias, promise) }
    AsyncFunction("signWithKey") { alias: String, message: String, prompt: String, promise: Promise -> signWithKey(alias, message, prompt, promise) }
    AsyncFunction("removeSigningKey") { alias: String -> remove(alias) }

    AsyncFunction("blobPut") { name: String, base64: String -> blobPut(name, base64) }

    AsyncFunction("blobGet") { name: String -> blobGet(name) }

    AsyncFunction("blobDelete") { name: String -> blobDelete(name) }

    AsyncFunction("blobList") { prefix: String -> blobList(prefix) }
  }

  private fun context(): Context = appContext.reactContext ?: throw IllegalStateException("no React context")

  private fun keyStore(): KeyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }

  // ── availability ──────────────────────────────────────────────────────

  private fun availability(): Map<String, Any?> {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return mapOf("available" to false, "reason" to "system-too-old")
    val keyguard = context().getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
    if (!keyguard.isDeviceSecure) return mapOf("available" to false, "reason" to "no-screen-lock")
    return mapOf("available" to true, "reason" to null)
  }

  // ── the root ──────────────────────────────────────────────────────────

  @RequiresApi(Build.VERSION_CODES.S)
  private fun spec(alias: String, strongBox: Boolean): KeyGenParameterSpec =
    KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_AGREE_KEY)
      .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
      .setUserAuthenticationRequired(true)
      // A positive window: biometric enrolment changes do not destroy the root.
      .setUserAuthenticationParameters(AUTH_WINDOW_SECONDS, KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL)
      .setIsStrongBoxBacked(strongBox)
      .build()

  @RequiresApi(Build.VERSION_CODES.S)
  private fun generate(alias: String, strongBox: Boolean): java.security.KeyPair {
    val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE)
    generator.initialize(spec(alias, strongBox))
    return generator.generateKeyPair()
  }

  private fun create(alias: String, promise: Promise) {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
      promise.reject("E_SYSTEM_TOO_OLD", "key agreement in the Keystore needs Android 12", null)
      return
    }
    try {
      val ks = keyStore()
      if (ks.containsAlias(alias)) {
        promise.reject("E_EXISTS", "a root already exists", null)
        return
      }
      val pair = try {
        generate(alias, strongBox = true)
      } catch (e: Exception) {
        // No StrongBox, or StrongBox without key agreement: the trusted environment.
        ks.deleteEntry(alias)
        generate(alias, strongBox = false)
      }
      if (securityLevel(pair.private) == KeyProperties.SECURITY_LEVEL_SOFTWARE) {
        ks.deleteEntry(alias)
        promise.reject("E_NO_SECURE_HARDWARE", "this phone would keep the key in software", null)
        return
      }
      promise.resolve(base64url(uncompressed(pair.public as ECPublicKey)))
    } catch (e: Exception) {
      promise.reject("E_CREATE", e.message ?: "could not make the root", e)
    }
  }

  @RequiresApi(Build.VERSION_CODES.S)
  private fun securityLevel(key: PrivateKey): Int {
    val info = KeyFactory.getInstance(key.algorithm, KEYSTORE).getKeySpec(key, KeyInfo::class.java)
    return info.securityLevel
  }

  private fun publicKeyOf(alias: String): String? {
    val pub = keyStore().getCertificate(alias)?.publicKey as? ECPublicKey ?: return null
    return base64url(uncompressed(pub))
  }

  private fun whereOf(alias: String): String? {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return null
    val key = keyStore().getKey(alias, null) as? PrivateKey ?: return null
    return if (securityLevel(key) == KeyProperties.SECURITY_LEVEL_STRONGBOX) "strongbox" else "trusted-environment"
  }

  private fun agree(alias: String, peer: String, promptText: String, promise: Promise) {
    val activity = appContext.currentActivity as? FragmentActivity
    if (activity == null) {
      promise.reject("E_NO_ACTIVITY", "no screen to ask on", null)
      return
    }
    val peerKey: PublicKey
    try {
      peerKey = peerPublicKey(alias, peer)
    } catch (e: Exception) {
      promise.reject("E_BAD_PEER", e.message ?: "bad peer key", e)
      return
    }
    activity.runOnUiThread {
      val callback = object : BiometricPrompt.AuthenticationCallback() {
        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
          try {
            val agreement = KeyAgreement.getInstance("ECDH", KEYSTORE)
            agreement.init(keyStore().getKey(alias, null) as PrivateKey)
            agreement.doPhase(peerKey, true)
            promise.resolve(base64url(agreement.generateSecret()))
          } catch (e: Exception) {
            promise.reject("E_AGREE", e.message ?: "key agreement failed", e)
          }
        }

        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
          promise.reject("E_CANCELLED", errString.toString(), null)
        }
      }
      val info = BiometricPrompt.PromptInfo.Builder()
        .setTitle(promptText)
        .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL)
        .build()
      BiometricPrompt(activity, ContextCompat.getMainExecutor(activity), callback).authenticate(info)
    }
  }

  // ── signing keys (PL-2) ───────────────────────────────────────────────
  // Separate keys — one per place, one per copy of a yes — made for SIGNING
  // (PURPOSE_SIGN), never the root, which only agrees keys. ES256: SHA-256 and
  // ECDSA P-256 inside the Keystore, after the same fingerprint, face or screen
  // lock as the root. The signature comes back DER; the wallet makes it low-S.

  @RequiresApi(Build.VERSION_CODES.S)
  private fun signingSpec(alias: String, strongBox: Boolean): KeyGenParameterSpec =
    KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
      .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
      .setDigests(KeyProperties.DIGEST_SHA256)
      .setUserAuthenticationRequired(true)
      .setUserAuthenticationParameters(AUTH_WINDOW_SECONDS, KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL)
      .setIsStrongBoxBacked(strongBox)
      .build()

  @RequiresApi(Build.VERSION_CODES.S)
  private fun generateSigning(alias: String, strongBox: Boolean): java.security.KeyPair {
    val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE)
    generator.initialize(signingSpec(alias, strongBox))
    return generator.generateKeyPair()
  }

  private fun createSigningKey(alias: String, promise: Promise) {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
      promise.reject("E_SYSTEM_TOO_OLD", "signing keys in the Keystore need Android 12 here", null)
      return
    }
    try {
      val ks = keyStore()
      if (ks.containsAlias(alias)) {
        promise.reject("E_EXISTS", "a key with this name exists", null)
        return
      }
      val pair = try {
        generateSigning(alias, strongBox = true)
      } catch (e: Exception) {
        ks.deleteEntry(alias)
        generateSigning(alias, strongBox = false)
      }
      if (securityLevel(pair.private) == KeyProperties.SECURITY_LEVEL_SOFTWARE) {
        ks.deleteEntry(alias)
        promise.reject("E_NO_SECURE_HARDWARE", "this phone would keep the key in software", null)
        return
      }
      promise.resolve(mapOf("publicKey" to base64url(uncompressed(pair.public as ECPublicKey)), "where" to (whereOf(alias) ?: "trusted-environment")))
    } catch (e: Exception) {
      promise.reject("E_CREATE_SIGNING", e.message ?: "could not make the signing key", e)
    }
  }

  private fun signWithKey(alias: String, message: String, promptText: String, promise: Promise) {
    val activity = appContext.currentActivity as? FragmentActivity
    if (activity == null) {
      promise.reject("E_NO_ACTIVITY", "no screen to ask on", null)
      return
    }
    val data = try {
      Base64.decode(message, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
    } catch (e: Exception) {
      promise.reject("E_BAD_MESSAGE", "the message is not base64url", e)
      return
    }
    activity.runOnUiThread {
      val callback = object : BiometricPrompt.AuthenticationCallback() {
        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
          try {
            val signer = java.security.Signature.getInstance("SHA256withECDSA")
            signer.initSign(keyStore().getKey(alias, null) as PrivateKey)
            signer.update(data)
            promise.resolve(base64url(signer.sign()))
          } catch (e: Exception) {
            promise.reject("E_SIGN", e.message ?: "signing failed", e)
          }
        }

        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
          promise.reject("E_CANCELLED", errString.toString(), null)
        }
      }
      val info = BiometricPrompt.PromptInfo.Builder()
        .setTitle(promptText)
        .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL)
        .build()
      BiometricPrompt(activity, ContextCompat.getMainExecutor(activity), callback).authenticate(info)
    }
  }

  private fun peerPublicKey(alias: String, peer: String): PublicKey {
    val bytes = Base64.decode(peer, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
    require(bytes.size == 65 && bytes[0] == 0x04.toByte()) { "the peer key is not an uncompressed P-256 key" }
    val params = (keyStore().getCertificate(alias).publicKey as ECPublicKey).params
    val point = ECPoint(BigInteger(1, bytes.copyOfRange(1, 33)), BigInteger(1, bytes.copyOfRange(33, 65)))
    return KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(point, params))
  }

  private fun remove(alias: String): Boolean {
    val ks = keyStore()
    if (!ks.containsAlias(alias)) return false
    ks.deleteEntry(alias)
    return true
  }

  private fun uncompressed(pub: ECPublicKey): ByteArray {
    fun fixed(n: BigInteger): ByteArray {
      val raw = n.toByteArray()
      val out = ByteArray(32)
      val src = if (raw.size > 32) raw.copyOfRange(raw.size - 32, raw.size) else raw
      System.arraycopy(src, 0, out, 32 - src.size, src.size)
      return out
    }
    return byteArrayOf(0x04) + fixed(pub.w.affineX) + fixed(pub.w.affineY)
  }

  private fun base64url(bytes: ByteArray): String = Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)

  // ── the blob store: private, and out of backups ───────────────────────

  private fun storeDir(): File = File(context().noBackupFilesDir, STORE_DIR).apply { mkdirs() }

  private fun file(name: String): File {
    require(NAME.matches(name)) { "bad blob name" }
    return File(storeDir(), name)
  }

  private fun blobPut(name: String, base64: String) {
    val target = file(name)
    val tmp = File(storeDir(), "$name.tmp")
    tmp.writeBytes(Base64.decode(base64, Base64.NO_WRAP))
    if (!tmp.renameTo(target)) {
      target.delete()
      if (!tmp.renameTo(target)) throw IllegalStateException("could not write $name")
    }
  }

  private fun blobGet(name: String): String? {
    val f = file(name)
    return if (f.exists()) Base64.encodeToString(f.readBytes(), Base64.NO_WRAP) else null
  }

  private fun blobDelete(name: String) {
    file(name).delete()
  }

  private fun blobList(prefix: String): List<String> =
    storeDir().list()?.filter { it.startsWith(prefix) && !it.endsWith(".tmp") } ?: emptyList()
}
