package com.vulft.app.ui.list

import android.app.Application
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.vulft.app.SyncScheduler
import com.vulft.app.container
import com.vulft.app.data.Affected
import com.vulft.app.data.Reports
import com.vulft.app.data.Severity
import com.vulft.app.data.VulnItem
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.debounce
import kotlinx.coroutines.flow.mapLatest
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

enum class SortOrder(val label: String) {
  SEVERITY_DESC("Severity: high → low"),
  SEVERITY_ASC("Severity: low → high"),
  APP_ASC("Application name: A → Z"),
  APP_DESC("Application name: Z → A"),
  NEWEST("Published: newest first"),
  OLDEST("Published: oldest first"),
  EPSS("Exploit probability (EPSS)"),
  UPDATED("Recently updated"),
}

data class ListFilter(
  val query: String = "",
  val severities: Set<String> = emptySet(),
  val packages: Set<String> = emptySet(),
  /** Default view: only actively exploited CVEs (CISA KEV or Microsoft). */
  val kevOnly: Boolean = true,
  val affectedOnly: Boolean = false,
  /** CVEs NVD changed that you haven't opened yet. */
  val updatedOnly: Boolean = false,
)

data class AppOption(val pkg: String, val label: String, val count: Int)

class CveListViewModel(app: Application) : AndroidViewModel(app) {
  private val c = app.container
  val sort = MutableStateFlow(SortOrder.SEVERITY_DESC)
  val filter = MutableStateFlow(ListFilter())
  private val _selected = MutableStateFlow<Set<String>>(emptySet())
  val selected = _selected.asStateFlow()
  val message = MutableStateFlow<String?>(null)

  // One item per app + CVE: the same CVE from NVD, MSRC and OSV links is merged.
  // A sync writes many times in a row: wait for a short pause and drop stale work, so the list recalculates once.
  @OptIn(kotlinx.coroutines.FlowPreview::class, kotlinx.coroutines.ExperimentalCoroutinesApi::class)
  private val allItems = c.repo.rows.debounce(300).mapLatest { rows -> VulnItem.dedupe(rows.map(VulnItem::from)) }.flowOn(Dispatchers.Default)
    .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), null)

  /** By default CVEs that don't affect the installed version are hidden (Settings → "Show CVEs that don't affect my version"). */
  private val items = combine(allItems, c.settings.state) { list, s ->
    if (list == null || s.showNotAffected) list else list.filter { it.affected != Affected.NO }
  }.flowOn(Dispatchers.Default).stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), null)

  /** How many CVEs are hidden because they don't affect your installed version. */
  val hiddenNotAffected = combine(allItems, c.settings.state) { list, s ->
    if (list == null || s.showNotAffected) 0 else list.count { it.affected == Affected.NO }
  }.flowOn(Dispatchers.Default).stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), 0)

  fun setShowNotAffected(show: Boolean) = c.settings.update { it.copy(showNotAffected = show) }

  val appOptions = items.map { list ->
    list.orEmpty().groupBy { it.appPkg }.map { (pkg, l) -> AppOption(pkg, l.first().row.appLabel, l.size) }.sortedBy { it.label.lowercase() }
  }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

  val visible = combine(items, sort, filter) { list, s, f ->
    list?.let { applyFilterSort(it, s, f) }
  }.flowOn(Dispatchers.Default).stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), null)

  val totalCount = items.map { it?.size ?: 0 }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), 0)
  /** CVEs changed since the last sync that the user hasn't opened (drives the "Updated (N)" chip). */
  val updatedCount = items.map { list -> list.orEmpty().count { it.cve.updatedAt > 0 && !it.cve.updateSeen } }
    .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), 0)
  // Hidden source-link rows aren't apps of their own.
  val watchedCount = c.repo.apps.map { apps -> apps.count { it.watched && !com.vulft.app.data.isLinkPkg(it.packageName) } }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), -1)
  val syncProgress = SyncScheduler.progress(app).stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), null)
  val settings = c.settings.state

  private fun applyFilterSort(list: List<VulnItem>, s: SortOrder, f: ListFilter): List<VulnItem> {
    val q = f.query.trim().lowercase()
    val filtered = list.filter { i ->
      (f.severities.isEmpty() || i.cve.severity in f.severities) &&
        (f.packages.isEmpty() || i.appPkg in f.packages) &&
        (!f.kevOnly || i.cve.exploited) &&
        (!f.affectedOnly || i.affected == Affected.YES) &&
        (!f.updatedOnly || (i.cve.updatedAt > 0 && !i.cve.updateSeen)) &&
        (q.isEmpty() || i.cve.id.lowercase().contains(q) || i.row.appLabel.lowercase().contains(q) || i.cve.description.lowercase().contains(q))
    }
    val bySeverity = compareBy<VulnItem>({ Severity.rank(it.cve.severity) }, { it.cve.cvssScore ?: 0.0 })
    val byApp = compareBy<VulnItem, String>(String.CASE_INSENSITIVE_ORDER) { it.row.appLabel }
    return when (s) {
      SortOrder.SEVERITY_DESC -> filtered.sortedWith(bySeverity.reversed().thenByDescending { it.cve.published })
      SortOrder.SEVERITY_ASC -> filtered.sortedWith(bySeverity.thenByDescending { it.cve.published })
      SortOrder.APP_ASC -> filtered.sortedWith(byApp.then(bySeverity.reversed()))
      SortOrder.APP_DESC -> filtered.sortedWith(byApp.reversed().then(bySeverity.reversed()))
      SortOrder.NEWEST -> filtered.sortedByDescending { it.cve.published }
      SortOrder.OLDEST -> filtered.sortedBy { it.cve.published }
      SortOrder.EPSS -> filtered.sortedByDescending { it.cve.epss ?: -1.0 }
      SortOrder.UPDATED -> filtered.sortedWith(compareByDescending<VulnItem> { it.cve.updatedAt }.thenByDescending { it.cve.lastModified })
    }
  }

  fun toggleSelect(key: String) = _selected.update { if (key in it) it - key else it + key }
  fun selectAllVisible() { _selected.value = visible.value.orEmpty().map { it.key }.toSet() }
  fun clearSelection() { _selected.value = emptySet() }
  fun syncNow() = SyncScheduler.runNow(getApplication())

  /** Selected items, or every visible item if nothing is selected. */
  private fun exportItems(): List<VulnItem> {
    val vis = visible.value.orEmpty()
    val sel = _selected.value
    return if (sel.isEmpty()) vis else vis.filter { it.key in sel }
  }

  fun exportCount(): Int = exportItems().size

  fun export(uri: Uri, json: Boolean) = viewModelScope.launch {
    val list = exportItems()
    runCatching {
      withContext(Dispatchers.IO) {
        val text = if (json) Reports.json(list) else Reports.csv(list)
        getApplication<Application>().contentResolver.openOutputStream(uri)!!.use { it.write(text.toByteArray()) }
      }
    }.onSuccess { message.value = "Exported ${list.size} CVEs" }.onFailure { message.value = "Export failed: ${it.message}" }
  }

  fun email() = viewModelScope.launch {
    val list = exportItems()
    val smtp = c.settings.current.smtp
    if (smtp.host.isBlank()) { message.value = "Set up the email server in Settings first"; return@launch }
    if (smtp.recipientList().isEmpty()) { message.value = "Add recipients in Settings → Email alerts → Send to"; return@launch }
    message.value = "Sending email…"
    runCatching { c.emailReport("Vulnerability report", list) }
      .onSuccess { message.value = "Emailed ${list.size} CVEs" }
      .onFailure { message.value = "Email failed: ${it.message}" }
  }
}
