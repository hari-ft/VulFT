package com.vulft.app.data

import android.content.Context
import androidx.core.content.edit
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.serialization.Serializable

@Serializable
data class SmtpConfig(
  val host: String = "",
  val port: Int = 587,
  /** NONE, STARTTLS or SSL */
  val security: String = "STARTTLS",
  val username: String = "",
  val password: String = "",
  val from: String = "",
  /** Comma-separated recipient addresses. */
  val recipients: String = "",
) {
  val isConfigured: Boolean get() = host.isNotBlank() && recipientList().isNotEmpty()
  fun recipientList(): List<String> = recipients.split(',', ';', ' ', '\n').map { it.trim() }.filter { it.isNotEmpty() }
}

@Serializable
data class AlertRules(
  val enabled: Boolean = false,
  val severities: Set<String> = setOf("CRITICAL", "HIGH"),
  /** true = every watched app; false = only [packages]. */
  val allApps: Boolean = true,
  val packages: Set<String> = emptySet(),
  /** Empty = every category. */
  val categories: Set<String> = emptySet(),
  val kevOnly: Boolean = false,
  val affectedOnly: Boolean = false,
) {
  fun matches(item: VulnItem): Boolean {
    val r = item.row
    if (severities.isNotEmpty() && r.cve.severity !in severities) return false
    if (!allApps && item.appPkg !in packages) return false
    if (categories.isNotEmpty() && r.appCategory !in categories) return false
    if (kevOnly && !r.cve.exploited) return false
    if (affectedOnly && item.affected == Affected.NO) return false
    return true
  }
}

@Serializable
data class AppSettings(
  /** Entered by the user in Settings; never compiled into the APK. */
  val nvdApiKey: String = "",
  val githubToken: String = "",
  val syncHours: Int = 24,
  /** Show CVEs for apps on this device without having to tick them. */
  val autoMonitor: Boolean = true,
  val autoUserApps: Boolean = true,
  val autoSystemApps: Boolean = false,
  /** Show CVEs whose vulnerable versions don't include the installed version (off = hidden). */
  val showNotAffected: Boolean = false,
  /** Check this phone's Android OS against Android Security Bulletins (OSV). */
  val autoAndroidOs: Boolean = true,
  /** How far back the first Microsoft (MSRC) sync of a product goes. */
  val msrcMonths: Int = 6,
  val smtp: SmtpConfig = SmtpConfig(),
  val alerts: AlertRules = AlertRules(),
  val lastSync: Long = 0,
  val lastSyncStatus: String = "",
  /** EPSS publishes once a day: all scores are refreshed at most daily, new CVEs every sync. */
  val lastEpssRefresh: Long = 0,
  /** Phone notification when a tracked app/product has a critical, actively exploited CVE. */
  val notifyCriticalExploited: Boolean = true,
  /** Also notify for High severity (not just Critical). */
  val notifyIncludeHigh: Boolean = false,
) {
  val effectiveNvdKey: String get() = nvdApiKey
  val effectiveGithubToken: String get() = githubToken
}

/**
 * Settings as JSON in SharedPreferences (backup disabled, so it stays on the device).
 * Secrets – SMTP password, NVD API key, GitHub token – are stored separately, encrypted with
 * an AES key that lives in the Android Keystore; the JSON only ever holds blanks for them.
 */
class SettingsStore(context: Context) {
  private val prefs = context.getSharedPreferences("vulft_settings", Context.MODE_PRIVATE)
  private val _state = MutableStateFlow(load())
  val state: StateFlow<AppSettings> = _state.asStateFlow()
  val current: AppSettings get() = _state.value

  private fun load(): AppSettings {
    val plain = prefs.getString("settings", null)?.let { runCatching { AppJson.decodeFromString(AppSettings.serializer(), it) }.getOrNull() } ?: AppSettings()
    fun secret(key: String, legacy: String) = prefs.getString(key, null)?.let { SecretBox.decrypt(it) } ?: legacy
    // Older versions stored secrets in the JSON ("legacy"); they're moved to encrypted storage on the next save.
    val s = plain.copy(
      nvdApiKey = secret(K_NVD, plain.nvdApiKey),
      githubToken = secret(K_GH, plain.githubToken),
      smtp = plain.smtp.copy(password = secret(K_SMTP, plain.smtp.password)),
    )
    if (plain.nvdApiKey.isNotEmpty() || plain.githubToken.isNotEmpty() || plain.smtp.password.isNotEmpty()) persist(s)
    return s
  }

  private fun persist(s: AppSettings) {
    val stripped = s.copy(nvdApiKey = "", githubToken = "", smtp = s.smtp.copy(password = ""))
    prefs.edit {
      putString("settings", AppJson.encodeToString(AppSettings.serializer(), stripped))
      putString(K_NVD, SecretBox.encrypt(s.nvdApiKey))
      putString(K_GH, SecretBox.encrypt(s.githubToken))
      putString(K_SMTP, SecretBox.encrypt(s.smtp.password))
    }
  }

  @Synchronized
  fun update(transform: (AppSettings) -> AppSettings) {
    _state.update(transform)
    persist(_state.value)
  }

  private companion object {
    const val K_NVD = "secret_nvd"
    const val K_GH = "secret_github"
    const val K_SMTP = "secret_smtp_password"
  }
}

/** AES-256-GCM with a non-exportable key in the Android Keystore. Output: base64(iv + ciphertext). */
object SecretBox {
  private const val ALIAS = "vulft_secrets"
  private const val TRANSFORM = "AES/GCM/NoPadding"

  private fun key(): javax.crypto.SecretKey {
    val ks = java.security.KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    (ks.getEntry(ALIAS, null) as? java.security.KeyStore.SecretKeyEntry)?.let { return it.secretKey }
    val gen = javax.crypto.KeyGenerator.getInstance(android.security.keystore.KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
    gen.init(
      android.security.keystore.KeyGenParameterSpec.Builder(ALIAS,
        android.security.keystore.KeyProperties.PURPOSE_ENCRYPT or android.security.keystore.KeyProperties.PURPOSE_DECRYPT)
        .setBlockModes(android.security.keystore.KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(android.security.keystore.KeyProperties.ENCRYPTION_PADDING_NONE)
        .setKeySize(256)
        .build(),
    )
    return gen.generateKey()
  }

  fun encrypt(plain: String): String {
    if (plain.isEmpty()) return ""
    val c = javax.crypto.Cipher.getInstance(TRANSFORM).apply { init(javax.crypto.Cipher.ENCRYPT_MODE, key()) }
    val out = c.iv + c.doFinal(plain.toByteArray(Charsets.UTF_8))
    return android.util.Base64.encodeToString(out, android.util.Base64.NO_WRAP)
  }

  /** Null if it can't be decrypted (e.g. the key was reset); the user then re-enters the secret. */
  fun decrypt(stored: String): String? {
    if (stored.isEmpty()) return ""
    return runCatching {
      val data = android.util.Base64.decode(stored, android.util.Base64.NO_WRAP)
      val c = javax.crypto.Cipher.getInstance(TRANSFORM)
      c.init(javax.crypto.Cipher.DECRYPT_MODE, key(), javax.crypto.spec.GCMParameterSpec(128, data, 0, 12))
      String(c.doFinal(data, 12, data.size - 12), Charsets.UTF_8)
    }.getOrNull()
  }
}
