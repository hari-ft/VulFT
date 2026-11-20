package com.vulft.app.data

import android.content.Context
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

/** Small JSON-in-SharedPreferences store. allowBackup is off, so this stays on the device. */
class SettingsStore(context: Context) {
  private val prefs = context.getSharedPreferences("vulft_settings", Context.MODE_PRIVATE)
  private val _state = MutableStateFlow(load())
  val state: StateFlow<AppSettings> = _state.asStateFlow()
  val current: AppSettings get() = _state.value

  private fun load(): AppSettings =
    prefs.getString("settings", null)?.let { runCatching { AppJson.decodeFromString(AppSettings.serializer(), it) }.getOrNull() } ?: AppSettings()

  @Synchronized
  fun update(transform: (AppSettings) -> AppSettings) {
    _state.update(transform)
    prefs.edit().putString("settings", AppJson.encodeToString(AppSettings.serializer(), _state.value)).apply()
  }
}
