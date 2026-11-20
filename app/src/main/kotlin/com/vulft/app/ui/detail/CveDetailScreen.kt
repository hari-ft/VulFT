package com.vulft.app.ui.detail

import android.app.Application
import androidx.compose.foundation.clickable
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.Article
import androidx.compose.material.icons.automirrored.outlined.OpenInNew
import androidx.compose.material.icons.outlined.Speed
import androidx.compose.material.icons.outlined.Upload
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.compose.viewModel
import com.vulft.app.container
import com.vulft.app.data.Affected
import com.vulft.app.data.VulnItem
import com.vulft.app.data.cpeKey
import com.vulft.app.data.remote.GhAdvisory
import com.vulft.app.data.remote.GithubAdvisoryClient
import com.vulft.app.ui.common.AppIcon
import com.vulft.app.ui.common.BackTopBar
import com.vulft.app.ui.common.ExploitedBadge
import com.vulft.app.ui.common.InfoRow
import com.vulft.app.ui.common.RansomwareBadge
import com.vulft.app.ui.common.SectionCard
import com.vulft.app.ui.common.SeverityBadge
import com.vulft.app.ui.common.VersionStatus
import com.vulft.app.ui.common.pct
import com.vulft.app.ui.theme.MonoType
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

sealed interface GhState { data object Idle : GhState; data object Loading : GhState; data class Done(val list: List<GhAdvisory>) : GhState; data class Error(val msg: String) : GhState }

class CveDetailViewModel(app: Application, val cveId: String) : AndroidViewModel(app) {
  private val c = app.container
  val cve = c.repo.cve(cveId).stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), null)
  /** Every source's row (for "How to fix" from NVD, MSRC and OSV). */
  val rawApps = c.repo.rowsForCve(cveId).map { rows -> rows.map(VulnItem::from) }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())
  /** One entry per app. */
  val apps = rawApps.map { VulnItem.dedupe(it) }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())
  val github = MutableStateFlow<GhState>(GhState.Idle)
  val tracked = c.repo.apps.map { list -> list.filter { it.watched }.mapNotNull { it.cpeKey() }.toSet() }
    .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptySet())

  /** Monitor an affected product: NVD vendor:product, an OSV package or a Microsoft product. */
  fun monitor(vendor: String, product: String) = viewModelScope.launch {
    when (com.vulft.app.data.productSource(vendor, product)) {
      com.vulft.app.data.ProductSource.NVD -> c.repo.addManualProduct(vendor, product, "${vendor.replace('_', ' ')} ${product.replace('_', ' ')}", null)
      else -> c.repo.addSourceProduct(vendor, product, if (vendor == "msrc") product else "$product (${vendor.removePrefix("osv:")})", null)
    }
    com.vulft.app.SyncScheduler.runNow(getApplication())
  }

  val osvFixes = MutableStateFlow<List<String>?>(null)
  val osvLoading = MutableStateFlow(false)
  fun loadOsv() = viewModelScope.launch {
    osvLoading.value = true
    osvFixes.value = runCatching { c.repo.osvFixedVersions(cveId) }.getOrDefault(emptyList())
    osvLoading.value = false
  }

  /** Opening the CVE clears its green "Updated" mark (the banner on this screen stays). */
  init { viewModelScope.launch { c.repo.markUpdateSeen(cveId) } }

  fun loadGithub() = viewModelScope.launch {
    github.value = GhState.Loading
    github.value = runCatching { GithubAdvisoryClient.forCve(cveId, c.settings.current.effectiveGithubToken) }
      .fold({ GhState.Done(it) }, { GhState.Error(it.message ?: "error") })
  }
}

@Composable
fun CveDetailScreen(cveId: String, onBack: () -> Unit) {
  val app = LocalContext.current.applicationContext as Application
  val vm: CveDetailViewModel = viewModel(key = cveId) { CveDetailViewModel(app, cveId) }
  val cve by vm.cve.collectAsStateWithLifecycle()
  val apps by vm.apps.collectAsStateWithLifecycle()
  val rawApps by vm.rawApps.collectAsStateWithLifecycle()
  val gh by vm.github.collectAsStateWithLifecycle()
  val tracked by vm.tracked.collectAsStateWithLifecycle()
  val uri = LocalUriHandler.current
  val context = LocalContext.current

  Scaffold(topBar = {
    BackTopBar(cveId, onBack) {
      IconButton(onClick = {
        val send = android.content.Intent(android.content.Intent.ACTION_SEND).apply {
          type = "text/plain"
          putExtra(android.content.Intent.EXTRA_SUBJECT, cveId)
          putExtra(android.content.Intent.EXTRA_TEXT, "$cveId\n${cve?.description ?: ""}\nhttps://nvd.nist.gov/vuln/detail/$cveId")
        }
        context.startActivity(android.content.Intent.createChooser(send, "Share $cveId"))
      }) { Icon(Icons.Outlined.Upload, "Share") }
    }
  }) { padding ->
    val c = cve
    if (c == null) {
      Column(Modifier.padding(padding).fillMaxSize(), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.Center) { CircularProgressIndicator() }
      return@Scaffold
    }
    Column(Modifier.padding(padding).fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
      Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
          SeverityBadge(c.severity, c.cvssScore, large = true)
          if (c.exploited) ExploitedBadge("Actively exploited")
        }
        Text(c.status, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        // Which of the 7 databases contributed to this record.
        val srcs = (c.sourceList() + listOfNotNull("CISA KEV".takeIf { c.kev }, "EPSS".takeIf { c.epss != null })).distinct()
        if (srcs.isNotEmpty()) {
          Row(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalAlignment = Alignment.CenterVertically) {
            Text("Sources", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            srcs.forEach { s ->
              Text(s, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSecondaryContainer,
                modifier = Modifier.background(MaterialTheme.colorScheme.secondaryContainer, androidx.compose.foundation.shape.RoundedCornerShape(6.dp))
                  .padding(horizontal = 8.dp, vertical = 2.dp))
            }
          }
        }
        if (c.updatedAt > 0) com.vulft.app.ui.common.UpdatedBanner(c.updatedAt, c.updateNote)
        Text(c.description, style = MaterialTheme.typography.bodyLarge)
      }

      SectionCard("Scores") {
        InfoRow("CVSS", c.cvssScore?.let { "$it (v${c.cvssVersion})" } ?: "Not yet scored")
        c.exploitabilityScore?.let { InfoRow("Exploitability", it.toString()) }
        c.impactScore?.let { InfoRow("Impact", it.toString()) }
        c.cvssVector?.let {
          Text("Vector", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
          Text(it, style = MonoType.small)
          HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
        }
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
          Icon(Icons.Outlined.Speed, null, tint = MaterialTheme.colorScheme.onSurfaceVariant)
          Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text("EPSS ${pct(c.epss)}" + (c.epssPercentile?.let { " · percentile ${pct(it)}" } ?: ""), style = MaterialTheme.typography.titleSmall)
            LinearProgressIndicator(progress = { (c.epss ?: 0.0).toFloat() }, modifier = Modifier.fillMaxWidth(),
              trackColor = MaterialTheme.colorScheme.surfaceContainerHighest, drawStopIndicator = {})
            Text("Chance of exploitation in the next 30 days", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
          }
        }
      }

      if (c.kev) {
        SectionCard("CISA Known Exploited Vulnerability") {
          Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            ExploitedBadge()
            if (c.kevRansomware == "Known") RansomwareBadge()
          }
          c.kevName?.let { Text(it, style = MaterialTheme.typography.titleSmall) }
          InfoRow("Added", c.kevDateAdded ?: "–")
          InfoRow("Fix due", c.kevDueDate ?: "–")
          InfoRow("Ransomware", c.kevRansomware ?: "Unknown", divider = c.kevAction != null)
          c.kevAction?.let { Text(it, style = MaterialTheme.typography.bodyMedium) }
        }
      }

      if (c.msExploited) {
        SectionCard("Microsoft: exploitation detected") {
          ExploitedBadge()
          Text("Microsoft's Security Update Guide reports this vulnerability as exploited in the wild. Install the update below.",
            style = MaterialTheme.typography.bodyMedium)
        }
      }

      val fixes = rawApps.filter { it.fix != null }
      if (fixes.isNotEmpty()) {
        SectionCard("How to fix") {
          fixes.forEachIndexed { idx, i ->
            val f = i.fix!!
            Text(i.row.appLabel, style = MaterialTheme.typography.titleSmall)
            when {
              f.kb != null -> {
                InfoRow("Update", VulnItem.kbLabel(f.kb), divider = false)
                f.fixedBuild?.let { InfoRow("Fixed build", it, divider = false) }
                InfoRow("Your build", i.row.appVersion ?: "Not set – add it in Apps to monitor", divider = false)
                f.kbUrl?.let { url -> Link("Open update details") { uri.openUri(url) } }
              }
              f.fixedIn.isNotEmpty() -> InfoRow("Fixed in", f.fixedIn.joinToString(", "), divider = false)
              else -> Text("No fixed version listed yet.", style = MaterialTheme.typography.bodyMedium)
            }
            f.note?.let { Text(it, style = MonoType.small, color = MaterialTheme.colorScheme.onSurfaceVariant) }
            Text("Source: ${f.source}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            if (idx < fixes.lastIndex) HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
          }
        }
      }

      SectionCard("Your affected apps and products") {
        if (apps.isEmpty()) Text("None of your monitored apps or products is linked to this CVE.", style = MaterialTheme.typography.bodyMedium,
          color = MaterialTheme.colorScheme.onSurfaceVariant)
        apps.forEachIndexed { idx, i ->
          Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(16.dp)) {
            AppIcon(i.appPkg, i.row.appLabel)
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
              Text("${i.row.appLabel} ${i.row.appVersion ?: ""}", style = MaterialTheme.typography.titleSmall)
              VersionStatus(i.affected)
              if (i.rangeList.isNotEmpty()) Text("Vulnerable: " + i.rangeList.joinToString("; ") { it.describe() }, style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
          }
          if (idx < apps.lastIndex) HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
        }
      }

      val products = c.affectedProducts.split(",").filter { it.contains(':') }
      if (products.isNotEmpty()) {
        SectionCard("Affected products") {
          products.forEach { key ->
            // Keys: "vendor:product" (NVD), "osv:<ecosystem>:<package>" (OSV), "msrc:<product name>" (Microsoft).
            val (v, p) = when {
              key.startsWith("osv:") -> key.removePrefix("osv:").let { "osv:" + it.substringBefore(':') to it.substringAfter(':') }
              key.startsWith("msrc:") -> "msrc" to key.removePrefix("msrc:")
              else -> key.substringBefore(':') to key.substringAfter(':')
            }
            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
              Text(com.vulft.app.data.productKeyLabel(v, p), style = MonoType.medium, modifier = Modifier.weight(1f))
              when {
                "$v:$p" in tracked -> Text("Monitoring", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
                v == "osv:Android" -> Text("Phone OS", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                else -> OutlinedButton(onClick = { vm.monitor(v, p) }) { Text("Monitor") }
              }
            }
          }
        }
      }

      SectionCard("Details") {
        InfoRow("Published", c.published.replace('T', ' ').take(16))
        InfoRow("Modified", c.lastModified.replace('T', ' ').take(16), divider = c.cwes.isNotBlank())
        c.cwes.split(",").filter { it.isNotBlank() }.forEachIndexed { i, cwe ->
          InfoRow(if (i == 0) "Weakness" else "", cwe, divider = false) { uri.openUri("https://cwe.mitre.org/data/definitions/${cwe.removePrefix("CWE-")}.html") }
        }
      }

      if (c.id.startsWith("CVE-")) {
        val osv by vm.osvFixes.collectAsStateWithLifecycle()
        val osvLoading by vm.osvLoading.collectAsStateWithLifecycle()
        SectionCard("OSV.dev fixed versions") {
          when {
            osvLoading -> CircularProgressIndicator()
            osv == null -> OutlinedButton(onClick = vm::loadOsv) { Text("Look up in OSV.dev") }
            osv!!.isEmpty() -> Text("OSV has no package versions for this CVE (common for closed-source apps).", style = MaterialTheme.typography.bodyMedium)
            else -> osv!!.forEach { Text(it, style = MonoType.small) }
          }
        }
      }

      SectionCard("GitHub advisory") {
        when (val s = gh) {
          GhState.Idle -> OutlinedButton(onClick = vm::loadGithub) {
            Icon(Icons.AutoMirrored.Outlined.Article, null, Modifier.size(18.dp)); Spacer(Modifier.width(8.dp)); Text("Look up advisories")
          }
          GhState.Loading -> CircularProgressIndicator()
          is GhState.Error -> { Text("Failed: ${s.msg}", color = MaterialTheme.colorScheme.error); OutlinedButton(onClick = vm::loadGithub) { Text("Retry") } }
          is GhState.Done -> {
            if (s.list.isEmpty()) Text("No GitHub advisory for this CVE (common for closed-source apps).", style = MaterialTheme.typography.bodyMedium)
            s.list.forEach { a ->
              Link("${a.ghsaId} · ${a.severity ?: ""}") { uri.openUri(a.url) }
              Text(a.summary, style = MaterialTheme.typography.bodyMedium)
              a.packages.forEach { Text(it, style = MonoType.small) }
            }
          }
        }
      }

      SectionCard("References") {
        Link("Open on NVD") { uri.openUri("https://nvd.nist.gov/vuln/detail/${c.id}") }
        c.references().forEach { r ->
          Link(r.url + if (r.tags.isNotEmpty()) "  · ${r.tags.joinToString()}" else "") { uri.openUri(r.url) }
        }
      }
    }
  }
}

@Composable
private fun Link(text: String, onClick: () -> Unit) {
  Row(Modifier.fillMaxWidth().clickable(onClick = onClick).padding(vertical = 6.dp), verticalAlignment = Alignment.CenterVertically,
    horizontalArrangement = Arrangement.spacedBy(8.dp)) {
    Icon(Icons.AutoMirrored.Outlined.OpenInNew, null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(16.dp))
    Text(text, color = MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.bodySmall, maxLines = 2, overflow = TextOverflow.Ellipsis)
  }
}
