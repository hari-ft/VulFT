package com.vulft.app.ui.settings

import com.vulft.app.ui.common.outlinedCardBorder
import com.vulft.app.ui.common.outlinedCardColors
import android.app.Application
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.width
import androidx.compose.material3.HorizontalDivider
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.material3.TextButton
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.compose.viewModel
import com.vulft.app.SyncScheduler
import com.vulft.app.container
import com.vulft.app.data.AlertRules
import com.vulft.app.data.Mailer
import com.vulft.app.data.Severity
import com.vulft.app.data.SmtpConfig
import com.vulft.app.formatTime
import com.vulft.app.ui.common.BackTopBar
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

class SettingsViewModel(app: Application) : AndroidViewModel(app) {
  private val c = app.container
  val settings = c.settings.state
  /** Monitored apps and products (hidden source-link rows excluded, so each app appears once). */
  val watchedApps = c.repo.apps.map { list -> list.filter { it.watched && !com.vulft.app.data.isLinkPkg(it.packageName) } }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())
  val syncProgress = SyncScheduler.progress(app).stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), null)
  val message = MutableStateFlow<String?>(null)

  fun saveKeys(nvd: String, gh: String) { c.settings.update { it.copy(nvdApiKey = nvd.trim(), githubToken = gh.trim()) }; message.value = "Saved" }
  fun setSyncHours(h: Int) { c.settings.update { it.copy(syncHours = h) }; SyncScheduler.schedule(getApplication(), h, replace = true) }
  fun syncNow() = SyncScheduler.runNow(getApplication())

  /** Automatic monitoring of apps on this device. */
  fun setMsrcMonths(m: Int) = c.settings.update { it.copy(msrcMonths = m) }

  fun setNotify(enabled: Boolean? = null, includeHigh: Boolean? = null) {
    c.settings.update { it.copy(notifyCriticalExploited = enabled ?: it.notifyCriticalExploited, notifyIncludeHigh = includeHigh ?: it.notifyIncludeHigh) }
    // Check right away against what's already synced.
    viewModelScope.launch { runCatching { com.vulft.app.CriticalNotifier.process(getApplication(), c.repo.currentItems(), c.settings.current) } }
  }

  fun setAuto(enabled: Boolean? = null, user: Boolean? = null, system: Boolean? = null, androidOs: Boolean? = null) {
    c.settings.update {
      it.copy(autoMonitor = enabled ?: it.autoMonitor, autoUserApps = user ?: it.autoUserApps, autoSystemApps = system ?: it.autoSystemApps,
        autoAndroidOs = androidOs ?: it.autoAndroidOs)
    }
    viewModelScope.launch {
      c.repo.refreshInstalledApps()
      if (c.repo.needsSync()) SyncScheduler.runNow(getApplication())
    }
  }

  fun setShowNotAffected(show: Boolean) = c.settings.update { it.copy(showNotAffected = show) }

  fun resetChoices() = viewModelScope.launch {
    c.repo.clearWatchChoices()
    if (c.repo.needsSync()) SyncScheduler.runNow(getApplication())
    message.value = "Manual choices cleared – automatic rule applied"
  }
  fun saveSmtp(cfg: SmtpConfig) { c.settings.update { it.copy(smtp = cfg) }; message.value = "SMTP settings saved" }
  fun saveAlerts(rules: AlertRules, recipients: String) {
    c.settings.update { it.copy(alerts = rules, smtp = it.smtp.copy(recipients = recipients.trim())) }
    message.value = "Alert settings saved"
  }

  fun testSmtp(cfg: SmtpConfig, to: List<String>) = viewModelScope.launch {
    message.value = "Sending test email…"
    runCatching { Mailer.send(cfg.copy(recipients = to.joinToString(",")), "[VulFT] Test email", "<p>Your VulFT SMTP settings work.</p>") }
      .onSuccess { message.value = "Test email sent to ${to.joinToString()}" }
      .onFailure { message.value = "Failed: ${it.message ?: it.javaClass.simpleName}" }
  }

  /** Email every current CVE matching the rules (not just new ones) to [recipients] as typed on screen. */
  fun sendDigest(rules: AlertRules, recipients: String) = viewModelScope.launch {
    val smtp = c.settings.current.smtp.copy(recipients = recipients)
    if (smtp.host.isBlank()) { message.value = "Set up the email server (SMTP) first"; return@launch }
    if (smtp.recipientList().isEmpty()) { message.value = "Add at least one address under Send to"; return@launch }
    val items = c.repo.currentItems().filter(rules::matches).sortedByDescending { Severity.rank(it.cve.severity) }
    if (items.isEmpty()) { message.value = "No CVEs match these rules"; return@launch }
    message.value = "Sending ${items.size} CVEs…"
    runCatching { Mailer.send(smtp, "[VulFT] Vulnerability digest (${items.size})", com.vulft.app.data.Reports.emailHtml("Vulnerability digest", items)) }
      .onSuccess { message.value = "Digest sent (${items.size} CVEs)" }
      .onFailure { message.value = "Failed: ${it.message}" }
  }

  suspend fun countMatching(rules: AlertRules): Int =
    kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.Default) { c.repo.currentItems().count(rules::matches) }
}

@Composable
private fun SettingsScaffold(
  title: String,
  onBack: () -> Unit,
  vm: SettingsViewModel,
  /** True when the screen has edits that haven't been saved. */
  dirty: Boolean = false,
  onSave: () -> Unit = {},
  content: @Composable () -> Unit,
) {
  val message by vm.message.collectAsStateWithLifecycle()
  val snackbar = remember { SnackbarHostState() }
  LaunchedEffect(message) { message?.let { snackbar.showSnackbar(it); vm.message.value = null } }
  // Leaving with unsaved edits asks first, instead of silently throwing them away.
  var confirmLeave by remember { mutableStateOf(false) }
  val tryBack = { if (dirty) confirmLeave = true else onBack() }
  androidx.activity.compose.BackHandler(enabled = dirty) { confirmLeave = true }
  if (confirmLeave) {
    androidx.compose.material3.AlertDialog(
      onDismissRequest = { confirmLeave = false },
      title = { Text("Save changes?") },
      text = { Text("You changed settings on this screen but didn't save them.") },
      confirmButton = { Button(onClick = { onSave(); confirmLeave = false; onBack() }) { Text("Save") } },
      dismissButton = {
        Row {
          TextButton(onClick = { confirmLeave = false; onBack() }) { Text("Discard") }
          TextButton(onClick = { confirmLeave = false }) { Text("Keep editing") }
        }
      },
    )
  }
  Scaffold(topBar = { BackTopBar(title, tryBack) }, snackbarHost = { SnackbarHost(snackbar) }) { padding ->
    Column(Modifier.padding(padding).fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
      content()
    }
  }
}

@Composable
private fun SectionCard(title: String, content: @Composable () -> Unit) {
  Card(Modifier.fillMaxWidth(), shape = MaterialTheme.shapes.medium, colors = outlinedCardColors(), border = outlinedCardBorder()) {
    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
      Text(title, style = MaterialTheme.typography.titleMedium)
      content()
    }
  }
}

@Composable
private fun NavRow(title: String, subtitle: String, onClick: () -> Unit) {
  Card(Modifier.fillMaxWidth().clickable(onClick = onClick), shape = MaterialTheme.shapes.medium, colors = outlinedCardColors(), border = outlinedCardBorder()) {
    Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
      Column(Modifier.weight(1f)) {
        Text(title, style = MaterialTheme.typography.titleMedium)
        Text(subtitle, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
      }
      Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, null)
    }
  }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun SettingsScreen(onBack: () -> Unit, onOpenApps: () -> Unit, onOpenCatalog: () -> Unit, onOpenSmtp: () -> Unit, onOpenAlerts: () -> Unit,
  onOpenPermissions: () -> Unit, vm: SettingsViewModel = viewModel()) {
  val s by vm.settings.collectAsStateWithLifecycle()
  val watched by vm.watchedApps.collectAsStateWithLifecycle()
  val progress by vm.syncProgress.collectAsStateWithLifecycle()
  var nvd by remember { mutableStateOf(s.nvdApiKey) }
  var gh by remember { mutableStateOf(s.githubToken) }

  SettingsScaffold("Settings", onBack, vm) {
    NavRow("Apps to monitor", "${watched.size} monitored · link apps to NVD, Microsoft or OSV.dev", onOpenApps)
    NavRow("Email server (SMTP)", if (s.smtp.host.isNotBlank()) "${s.smtp.host}:${s.smtp.port}" else "Not configured", onOpenSmtp)
    NavRow("Email alerts", (if (s.alerts.enabled) "On · ${s.alerts.severities.joinToString { Severity.label(it) }}" else "Off") +
      " · ${s.smtp.recipientList().size} recipients", onOpenAlerts)
    NavRow("App permissions", "What VulFT is allowed to do, notifications, and whether background sync can run", onOpenPermissions)

    SectionCard("Phone notifications") {
      val ctx = androidx.compose.ui.platform.LocalContext.current
      Row(verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
          Text("Critical + actively exploited", style = MaterialTheme.typography.bodyLarge)
          Text("Notify me when an app or product I track has a critical CVE that's being exploited (CISA KEV or Microsoft). Each one once.",
            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Switch(s.notifyCriticalExploited, { vm.setNotify(enabled = it) })
      }
      Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()
        .clickable(enabled = s.notifyCriticalExploited) { vm.setNotify(includeHigh = !s.notifyIncludeHigh) }) {
        Checkbox(s.notifyIncludeHigh, { vm.setNotify(includeHigh = it) }, enabled = s.notifyCriticalExploited)
        Text("Also High severity", style = MaterialTheme.typography.bodyMedium)
      }
      if (s.notifyCriticalExploited && !com.vulft.app.CriticalNotifier.canNotify(ctx)) {
        Text("Notifications are blocked for VulFT. Allow them in App permissions.", style = MaterialTheme.typography.bodySmall,
          color = MaterialTheme.colorScheme.error)
        OutlinedButton(onClick = onOpenPermissions) { Text("Open App permissions") }
      }
    }

    SectionCard("Apps on this device") {
      Row(verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
          Text("Show CVEs for installed apps", style = MaterialTheme.typography.bodyLarge)
          Text("Monitors apps automatically when they're linked to a data source (NVD, Microsoft or OSV.dev). No need to tick them.",
            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Switch(s.autoMonitor, { vm.setAuto(enabled = it) })
      }
      Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth().clickable(enabled = s.autoMonitor) { vm.setAuto(user = !s.autoUserApps) }) {
        Checkbox(s.autoUserApps, { vm.setAuto(user = it) }, enabled = s.autoMonitor)
        Column {
          Text("User apps", style = MaterialTheme.typography.bodyMedium)
          Text("Apps you can open, including preinstalled ones like the browser", style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
      }
      Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth().clickable(enabled = s.autoMonitor) { vm.setAuto(system = !s.autoSystemApps) }) {
        Checkbox(s.autoSystemApps, { vm.setAuto(system = it) }, enabled = s.autoMonitor)
        Column {
          Text("System apps", style = MaterialTheme.typography.bodyMedium)
          Text("Background components without a launcher icon (e.g. WebView)", style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
      }
      Row(verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
          Text("Show CVEs that don't affect my version", style = MaterialTheme.typography.bodyLarge)
          Text("Off: CVEs for older versions you've already updated past are hidden. CVEs where the version can't be checked are always shown.",
            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Switch(s.showNotAffected, { vm.setShowNotAffected(it) })
      }
      Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth().clickable(enabled = s.autoMonitor) { vm.setAuto(androidOs = !s.autoAndroidOs) }) {
        Checkbox(s.autoAndroidOs, { vm.setAuto(androidOs = it) }, enabled = s.autoMonitor)
        Column {
          Text("This phone's Android OS", style = MaterialTheme.typography.bodyMedium)
          Text("Android ${android.os.Build.VERSION.RELEASE}, security patch ${android.os.Build.VERSION.SECURITY_PATCH} – checked against Android Security Bulletins (OSV.dev)",
            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
      }
      Text("Apps you tick or untick in 'Apps to monitor' keep your choice.", style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant)
      OutlinedButton(onClick = vm::resetChoices) { Text("Reset my manual choices") }
    }

    SectionCard("Sync") {
      Text("Last sync: ${formatTime(s.lastSync)}", style = MaterialTheme.typography.bodyMedium)
      if (s.lastSyncStatus.isNotBlank()) Text(s.lastSyncStatus, style = MaterialTheme.typography.bodySmall,
        color = if (s.lastSyncStatus.startsWith("Failed")) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant)
      progress?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.primary) }
      Text("Automatic sync every:", style = MaterialTheme.typography.bodyMedium)
      FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
        listOf(1, 2, 3, 6, 12, 24, 48).forEach { h -> FilterChip(selected = s.syncHours == h, onClick = { vm.setSyncHours(h) }, label = { Text("${h}h") }) }
      }
      if (s.syncHours <= 3) {
        Text("Frequent syncs use more data and battery. Without an NVD API key each NVD request is rate-limited, so hourly syncs take longer.",
          style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
      }
      Button(onClick = vm::syncNow, enabled = progress == null) { Text("Sync now") }
    }

    SectionCard("Data sources") {
      listOf(
        "NVD" to "All published CVEs, scores and affected versions (key optional, faster with one)",
        "OSV.dev" to "Open-source packages (PyPI, npm, Maven, Go, NuGet, Debian, Ubuntu…) with exact fixed versions",
        "Android Security Bulletins" to "Google's monthly Android OS fixes, checked against this phone's security patch level (delivered via OSV.dev)",
        "Microsoft MSRC" to "Windows, Office, Edge, Teams, .NET… with the KB update and fixed build",
        "CISA KEV" to "Vulnerabilities being actively exploited",
        "FIRST EPSS" to "Chance of exploitation in the next 30 days",
        "GitHub Advisories" to "Package advisories on the CVE detail page (token optional)",
      ).forEach { (name, what) ->
        Row(verticalAlignment = Alignment.Top) {
          Text(name, style = MaterialTheme.typography.titleSmall, modifier = Modifier.width(130.dp))
          Text(what, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
      }
      Text("Microsoft history on first sync", style = MaterialTheme.typography.bodyMedium)
      FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
        listOf(6, 12, 24).forEach { m -> FilterChip(selected = s.msrcMonths == m, onClick = { vm.setMsrcMonths(m) }, label = { Text("$m months") }) }
      }
      HorizontalDivider()
      OutlinedTextField(nvd, { nvd = it }, label = { Text("NVD API key") }, singleLine = true, modifier = Modifier.fillMaxWidth(),
        placeholder = { Text(if (s.nvdApiKey.isNotBlank()) "Saved" else "Not set: sync is ~10x slower") },
        visualTransformation = PasswordVisualTransformation())
      OutlinedTextField(gh, { gh = it }, label = { Text("GitHub token (optional)") }, singleLine = true, modifier = Modifier.fillMaxWidth(),
        placeholder = { Text(if (s.githubToken.isNotBlank()) "Saved" else "Not set (optional)") },
        visualTransformation = PasswordVisualTransformation())
      Text("Keys are stored only on this device. Get a free NVD key at nvd.nist.gov/developers/request-an-api-key.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
      OutlinedButton(onClick = { vm.saveKeys(nvd, gh) }) { Text("Save keys") }
    }
  }
}

@Composable
fun SmtpScreen(onBack: () -> Unit, vm: SettingsViewModel = viewModel()) {
  val s by vm.settings.collectAsStateWithLifecycle()
  var host by remember { mutableStateOf(s.smtp.host) }
  var port by remember { mutableStateOf(s.smtp.port.toString()) }
  var security by remember { mutableStateOf(s.smtp.security) }
  var user by remember { mutableStateOf(s.smtp.username) }
  var pass by remember { mutableStateOf(s.smtp.password) }
  var from by remember { mutableStateOf(s.smtp.from) }
  // Recipients are edited in Email alerts; keep whatever is saved there.
  val cfg = SmtpConfig(host.trim(), port.toIntOrNull() ?: 587, security, user.trim(), pass, from.trim(), s.smtp.recipients)

  SettingsScaffold("Email server (SMTP)", onBack, vm, dirty = cfg != s.smtp, onSave = { vm.saveSmtp(cfg) }) {
    SectionCard("Server") {
      OutlinedTextField(host, { host = it }, label = { Text("SMTP host (e.g. smtp.gmail.com)") }, singleLine = true, modifier = Modifier.fillMaxWidth())
      OutlinedTextField(port, { port = it.filter(Char::isDigit) }, label = { Text("Port") }, singleLine = true, modifier = Modifier.fillMaxWidth(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number))
      Text("Security", style = MaterialTheme.typography.bodyMedium)
      listOf("STARTTLS" to "STARTTLS (port 587)", "SSL" to "SSL/TLS (port 465)", "NONE" to "None (port 25)").forEach { (v, l) ->
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.clickable {
          security = v; port = when (v) { "SSL" -> "465"; "NONE" -> "25"; else -> "587" }
        }) { RadioButton(security == v, null); Text(l, Modifier.padding(start = 8.dp)) }
      }
    }
    SectionCard("Login") {
      OutlinedTextField(user, { user = it }, label = { Text("Username") }, singleLine = true, modifier = Modifier.fillMaxWidth())
      OutlinedTextField(pass, { pass = it }, label = { Text("Password / app password") }, singleLine = true, modifier = Modifier.fillMaxWidth(),
        visualTransformation = PasswordVisualTransformation(), keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password))
      Text("Gmail/Outlook: use an app password, not your normal password.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
    SectionCard("Addresses") {
      OutlinedTextField(from, { from = it }, label = { Text("From address (default: username)") }, singleLine = true, modifier = Modifier.fillMaxWidth(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Email))
      Text("Who receives alerts is set in Email alerts.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
    var askTo by remember { mutableStateOf(false) }
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
      Button(onClick = { vm.saveSmtp(cfg) }) { Text("Save") }
      OutlinedButton(onClick = { askTo = true }, enabled = cfg.host.isNotBlank()) { Text("Send test email") }
    }

    // Ask where to send the test; pre-filled with the alert recipients, if any.
    if (askTo) {
      var to by remember { mutableStateOf(cfg.recipients) }
      val list = SmtpConfig(recipients = to).recipientList()
      val valid = list.isNotEmpty() && list.all { Regex("""^[^@\s]+@[^@\s]+\.[^@\s]+$""").matches(it) }
      androidx.compose.material3.AlertDialog(
        onDismissRequest = { askTo = false },
        title = { Text("Send test email") },
        text = {
          Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedTextField(to, { to = it }, label = { Text("To") }, placeholder = { Text("you@example.com") }, singleLine = true,
              modifier = Modifier.fillMaxWidth(), keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Email),
              isError = to.isNotBlank() && !valid)
            Text("Separate several addresses with commas. This doesn't change who receives alerts.",
              style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
          }
        },
        confirmButton = { Button(onClick = { vm.testSmtp(cfg, list); askTo = false }, enabled = valid) { Text("Send") } },
        dismissButton = { TextButton(onClick = { askTo = false }) { Text("Cancel") } },
      )
    }
  }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun AlertRulesScreen(onBack: () -> Unit, vm: SettingsViewModel = viewModel()) {
  val s by vm.settings.collectAsStateWithLifecycle()
  val watched by vm.watchedApps.collectAsStateWithLifecycle()
  var rules by remember { mutableStateOf(s.alerts) }
  var sendTo by remember { mutableStateOf(s.smtp.recipients) }
  var matchCount by remember { mutableStateOf<Int?>(null) }
  LaunchedEffect(rules) { matchCount = vm.countMatching(rules) }
  val categories = watched.map { it.category }.distinct().sorted()

  SettingsScaffold("Email alerts", onBack, vm, dirty = rules != s.alerts || sendTo.trim() != s.smtp.recipients.trim(),
    onSave = { vm.saveAlerts(rules, sendTo) }) {
    SectionCard("Alerts") {
      Row(verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
          Text("Email me about new CVEs")
          Text("Checked after every sync. Only CVEs found after an app's first sync count as new.", style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Switch(rules.enabled, { rules = rules.copy(enabled = it) })
      }
      if (s.smtp.host.isBlank()) Text("The email server (SMTP) is not set up yet, so no email can be sent.", color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
    }

    SectionCard("Send to") {
      OutlinedTextField(sendTo, { sendTo = it }, label = { Text("Email addresses") }, placeholder = { Text("you@example.com, team@example.com") },
        modifier = Modifier.fillMaxWidth(), keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Email))
      val count = SmtpConfig(recipients = sendTo).recipientList().size
      Text(if (count == 0) "Separate several addresses with commas." else "$count recipient${if (count == 1) "" else "s"}",
        style = MaterialTheme.typography.bodySmall, color = if (count == 0 && rules.enabled) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant)
    }

    SectionCard("Severity") {
      FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
        Severity.all.forEach { sev ->
          val on = sev in rules.severities
          FilterChip(on, { rules = rules.copy(severities = if (on) rules.severities - sev else rules.severities + sev) }, label = { Text(Severity.label(sev)) })
        }
      }
      Text("None selected = any severity.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }

    SectionCard("Category") {
      if (categories.isEmpty()) Text("Monitor some apps first.", style = MaterialTheme.typography.bodySmall)
      FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
        categories.forEach { cat ->
          val on = cat in rules.categories
          FilterChip(on, { rules = rules.copy(categories = if (on) rules.categories - cat else rules.categories + cat) }, label = { Text(cat) })
        }
      }
      Text("None selected = all categories.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }

    SectionCard("Apps") {
      Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.clickable { rules = rules.copy(allApps = true) }) {
        RadioButton(rules.allApps, null); Text("All monitored apps", Modifier.padding(start = 8.dp))
      }
      Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.clickable { rules = rules.copy(allApps = false) }) {
        RadioButton(!rules.allApps, null); Text("Only these apps:", Modifier.padding(start = 8.dp))
      }
      if (!rules.allApps) {
        watched.forEach { a ->
          val on = a.packageName in rules.packages
          Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth().clickable {
            rules = rules.copy(packages = if (on) rules.packages - a.packageName else rules.packages + a.packageName)
          }) { Checkbox(on, null); Text(a.label, Modifier.padding(start = 8.dp)) }
        }
      }
    }

    SectionCard("Extra conditions") {
      Row(verticalAlignment = Alignment.CenterVertically) {
        Text("Only actively exploited (CISA KEV)", Modifier.weight(1f)); Switch(rules.kevOnly, { rules = rules.copy(kevOnly = it) })
      }
      Row(verticalAlignment = Alignment.CenterVertically) {
        Text("Skip CVEs that don't affect my installed version", Modifier.weight(1f)); Switch(rules.affectedOnly, { rules = rules.copy(affectedOnly = it) })
      }
    }

    Text("${matchCount ?: "…"} current CVEs match these rules.", style = MaterialTheme.typography.bodyMedium)
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
      Button(onClick = { vm.saveAlerts(rules, sendTo) }) { Text("Save") }
      OutlinedButton(onClick = { vm.sendDigest(rules, sendTo) }, enabled = s.smtp.host.isNotBlank() && sendTo.isNotBlank()) { Text("Email matching CVEs now") }
    }
  }
}
