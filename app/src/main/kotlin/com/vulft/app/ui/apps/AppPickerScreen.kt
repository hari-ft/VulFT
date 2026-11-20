package com.vulft.app.ui.apps

import com.vulft.app.ui.theme.JetBrainsMono
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.Spacer
import com.vulft.app.ui.common.AppIcon
import android.app.Application
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.compose.viewModel
import com.vulft.app.container
import com.vulft.app.data.AppEntry
import com.vulft.app.data.cpeKey
import com.vulft.app.data.isManualProduct
import com.vulft.app.data.source
import com.vulft.app.data.isLink
import com.vulft.app.data.remote.CpeSuggestion
import com.vulft.app.ui.common.BackTopBar
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

enum class AppFilter(val label: String) { USER("User apps"), SYSTEM("System apps"), WATCHED("Monitored"), MAPPED("Has data source"), WITH_CVES("Has CVEs"), ADDED("Added products") }

/** An app row: the app plus its extra source links (Microsoft, OSV, more NVD products). */
data class AppUi(val app: AppEntry, val cveCount: Int, val links: List<AppEntry> = emptyList()) {
  val isLinked: Boolean get() = app.cpeKey() != null || links.isNotEmpty()
}

class AppPickerViewModel(app: Application) : AndroidViewModel(app) {
  private val repo = app.container.repo
  val query = MutableStateFlow("")
  val filters = MutableStateFlow(setOf(AppFilter.USER))
  val loading = MutableStateFlow(false)

  val apps = combine(repo.apps, repo.cveCounts, query, filters) { apps, counts, q, f ->
    val countMap = counts.associate { it.cpeKey to it.n }
    val linksByParent = apps.filter { it.isLink() }.groupBy { com.vulft.app.data.parentPkg(it.packageName) }
    apps.asSequence()
      .filter { !it.isLink() && (it.installed || it.isManualProduct()) }
      .map { a ->
        val links = linksByParent[a.packageName].orEmpty()
        AppUi(a, (listOfNotNull(a.cpeKey()) + links.mapNotNull { it.cpeKey() }).sumOf { countMap[it] ?: 0 }, links)
      }
      .filter { u ->
        val a = u.app
        val typeOk = when {
          AppFilter.USER in f && AppFilter.SYSTEM in f -> true
          AppFilter.USER in f -> !a.isSystem || a.watched || a.mappingSource == "builtin"
          AppFilter.SYSTEM in f -> a.isSystem
          else -> true
        }
        typeOk && (AppFilter.WATCHED !in f || a.watched) && (AppFilter.MAPPED !in f || u.isLinked) && (AppFilter.WITH_CVES !in f || u.cveCount > 0) && (AppFilter.ADDED !in f || a.isManualProduct()) &&
          (q.isBlank() || a.label.contains(q, true) || a.packageName.contains(q, true))
      }
      .sortedWith(compareByDescending<AppUi> { it.app.watched }.thenBy { it.app.label.lowercase() })
      .toList()
  }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), null)

  init { refresh() }

  fun refresh() = viewModelScope.launch { loading.value = true; runCatching { repo.refreshInstalledApps() }; loading.value = false }
  fun setWatched(pkg: String, on: Boolean) = viewModelScope.launch { repo.setWatched(pkg, on) }
  fun watchAllMapped() = viewModelScope.launch { repo.setWatched(apps.value.orEmpty().filter { it.app.cpeKey() != null }.map { it.app.packageName }, true) }
  fun unwatchAll() = viewModelScope.launch { repo.setWatched(apps.value.orEmpty().map { it.app.packageName }, false) }
  fun setMapping(pkg: String, vendor: String?, product: String?, watch: Boolean, version: String? = null) = viewModelScope.launch {
    repo.setMapping(pkg, vendor, product)
    if (version != null) repo.setVersion(pkg, version)
    if (watch) repo.setWatched(pkg, true)
  }
  fun addProduct(vendor: String, product: String, label: String, version: String) = viewModelScope.launch { repo.addManualProduct(vendor, product, label, version) }
  fun delete(pkg: String) = viewModelScope.launch { repo.deleteApp(pkg) }
  fun setVersion(pkg: String, version: String) = viewModelScope.launch {
    repo.setVersion(pkg, version)
    com.vulft.app.SyncScheduler.runNow(getApplication())
  }
  suspend fun search(q: String): List<CpeSuggestion> = repo.searchProducts(q)
  suspend fun searchMicrosoft(q: String) = repo.searchMicrosoftProducts(q)

  fun addLink(parent: String, vendor: String, product: String) = viewModelScope.launch {
    repo.addLink(parent, vendor, product)
    com.vulft.app.SyncScheduler.runNow(getApplication())
  }
  fun removeLink(linkPkg: String) = viewModelScope.launch { repo.removeLink(linkPkg) }
  fun clearMainLink(parent: String) = viewModelScope.launch { repo.clearMainLink(parent) }
}

@Composable
fun AppPickerScreen(onBack: () -> Unit, onOpenCatalog: () -> Unit, vm: AppPickerViewModel = viewModel()) {
  val apps by vm.apps.collectAsStateWithLifecycle()
  val query by vm.query.collectAsStateWithLifecycle()
  val filters by vm.filters.collectAsStateWithLifecycle()
  val loading by vm.loading.collectAsStateWithLifecycle()
  var menu by remember { mutableStateOf(false) }
  var mapping by remember { mutableStateOf<AppEntry?>(null) }
  var versionEdit by remember { mutableStateOf<AppEntry?>(null) }
  var linking by remember { mutableStateOf<AppUi?>(null) }

  Scaffold(
    topBar = {
      BackTopBar("Apps to monitor", onBack) {
        IconButton(onClick = vm::refresh) { Icon(Icons.Default.Refresh, "Rescan apps") }
        IconButton(onClick = { menu = true }) { Icon(Icons.Default.MoreVert, "More") }
        DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
          DropdownMenuItem(text = { Text("Monitor all listed apps with a CPE") }, onClick = { vm.watchAllMapped(); menu = false })
          DropdownMenuItem(text = { Text("Stop monitoring all listed apps") }, onClick = { vm.unwatchAll(); menu = false })
        }
      }
    },
    floatingActionButton = {
      ExtendedFloatingActionButton(onClick = onOpenCatalog, icon = { Icon(Icons.Default.Add, null) }, text = { Text("Browse all products") })
    },
  ) { padding ->
    Column(Modifier.padding(padding).fillMaxSize()) {
      OutlinedTextField(query, { vm.query.value = it }, placeholder = { Text("Search apps") }, singleLine = true,
        modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 4.dp))
      LazyRow(contentPadding = PaddingValues(horizontal = 12.dp), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
        items(AppFilter.entries) { f ->
          FilterChip(selected = f in filters, onClick = { vm.filters.value = if (f in filters) filters - f else filters + f }, label = { Text(f.label) })
        }
      }
      Text(
        "Tick an app to monitor it. Tap an app to link it to NVD, Microsoft (MSRC) or OSV.dev – an app can use several sources.",
        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
      )
      val list = apps
      if (list == null || (loading && list.isEmpty())) {
        Column(Modifier.fillMaxSize(), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.Center) { CircularProgressIndicator() }
      } else {
        LazyColumn(contentPadding = PaddingValues(bottom = 96.dp)) {
          items(list, key = { it.app.packageName }) { u ->
            val isInstalledApp = !u.app.isManualProduct() && u.app.packageName != com.vulft.app.data.DEVICE_OS_PKG
            AppRow(
              u,
              onToggle = { on -> if (on && !u.isLinked) linking = u else vm.setWatched(u.app.packageName, on) },
              onClick = {
                when {
                  isInstalledApp -> linking = u
                  u.app.source() == com.vulft.app.data.ProductSource.NVD -> mapping = u.app
                  else -> versionEdit = u.app
                }
              },
              onDelete = if (u.app.isManualProduct()) ({ vm.delete(u.app.packageName) }) else null,
            )
            HorizontalDivider()
          }
        }
      }
    }
  }

  linking?.let { start ->
    // Keep the dialog in sync with the live list (links added/removed while it's open).
    val u = apps.orEmpty().firstOrNull { it.app.packageName == start.app.packageName } ?: start
    LinkSourcesDialog(u, vm, onDismiss = { linking = null })
  }

  versionEdit?.let { app ->
    var v by remember(app.packageName) { mutableStateOf(app.versionName ?: "") }
    val src = app.source()
    androidx.compose.material3.AlertDialog(
      onDismissRequest = { versionEdit = null },
      title = { Text(app.label) },
      text = {
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
          Text("Source: ${src.label}\n${com.vulft.app.data.productKeyLabel(app.cpeVendor, app.cpeProduct)}", style = MaterialTheme.typography.bodySmall)
          if (src == com.vulft.app.data.ProductSource.ANDROID_OS) {
            Text("Checked against Android Security Bulletins using this phone's security patch level ($v). It updates automatically.",
              style = MaterialTheme.typography.bodyMedium)
          } else {
            OutlinedTextField(v, { v = it }, singleLine = true, modifier = Modifier.fillMaxWidth(),
              label = { Text(if (src == com.vulft.app.data.ProductSource.MSRC) "Your build number, e.g. 16.0.14334.21048" else "Your version") })
            Text(if (src == com.vulft.app.data.ProductSource.MSRC) "Compared with the fixed build of each KB update." else "OSV checks exactly which vulnerabilities affect this version.",
              style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
          }
        }
      },
      confirmButton = {
        if (src != com.vulft.app.data.ProductSource.ANDROID_OS) Button(onClick = { vm.setVersion(app.packageName, v); versionEdit = null }) { Text("Save") }
        else TextButton(onClick = { versionEdit = null }) { Text("OK") }
      },
      dismissButton = { if (src != com.vulft.app.data.ProductSource.ANDROID_OS) TextButton(onClick = { versionEdit = null }) { Text("Cancel") } },
    )
  }

  mapping?.let { app ->
    CpeDialog(
      title = "NVD product for ${app.label}",
      initialQuery = app.label,
      initialVendor = app.cpeVendor ?: "",
      initialProduct = app.cpeProduct ?: "",
      initialVersion = if (app.isManualProduct()) (app.versionName ?: "") else null,
      search = vm::search,
      onDismiss = { mapping = null },
      onClear = if (app.cpeKey() != null) ({ vm.setMapping(app.packageName, null, null, false); vm.setWatched(app.packageName, false); mapping = null }) else null,
      onSave = { v, p, ver -> vm.setMapping(app.packageName, v, p, watch = true, version = ver); mapping = null },
    )
  }

}

@Composable
private fun AppRow(u: AppUi, onToggle: (Boolean) -> Unit, onClick: () -> Unit, onDelete: (() -> Unit)?) {
  val a = u.app
  Row(Modifier.fillMaxWidth().heightIn(min = 72.dp).clickable(onClick = onClick).padding(horizontal = 8.dp, vertical = 8.dp),
    verticalAlignment = Alignment.CenterVertically) {
    Checkbox(checked = a.watched, onCheckedChange = onToggle)
    AppIcon(a.packageName, a.label)
    Spacer(Modifier.width(16.dp))
    Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
      Text(a.label, style = MaterialTheme.typography.titleSmall)
      Text("${a.packageName.removePrefix("manual:")} · ${a.versionName ?: "?"} · ${a.category}", style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant)
      // Every source this app is linked to: NVD, Microsoft, OSV.
      val sources = (listOfNotNull(a.cpeKey()?.let { a }) + u.links).map { it.source().label.substringBefore(" ·") }.distinct()
      Text(
        if (!u.isLinked) "Not linked – tap to link a source"
        else sources.joinToString(" + ") + (if (u.cveCount > 0) " · ${u.cveCount} CVEs" else "") +
          if (a.watched && a.watchChoice == null && !a.isManualProduct()) " · auto" else "",
        style = com.vulft.app.ui.theme.MonoType.small,
        color = if (!u.isLinked) MaterialTheme.colorScheme.outline else MaterialTheme.colorScheme.primary,
      )
    }
    if (onDelete != null) IconButton(onClick = onDelete) { Icon(Icons.Default.Delete, "Remove") }
  }
}

@Composable
internal fun CpeSearch(initialQuery: String, search: suspend (String) -> List<CpeSuggestion>, onPick: (CpeSuggestion) -> Unit) {
  val scope = rememberCoroutineScope()
  var q by remember { mutableStateOf(initialQuery) }
  var results by remember { mutableStateOf<List<CpeSuggestion>?>(null) }
  var busy by remember { mutableStateOf(false) }
  var error by remember { mutableStateOf<String?>(null) }
  val run: () -> Unit = {
    scope.launch {
      busy = true; error = null
      runCatching { search(q) }.onSuccess { results = it }.onFailure { error = it.message }
      busy = false
    }
  }
  LaunchedEffect(Unit) { if (initialQuery.isNotBlank()) run() }
  Row(verticalAlignment = Alignment.CenterVertically) {
    OutlinedTextField(q, { q = it }, label = { Text("Search NVD products") }, singleLine = true, modifier = Modifier.weight(1f))
    TextButton(onClick = run, enabled = !busy && q.isNotBlank()) { Text("Search") }
  }
  when {
    busy -> CircularProgressIndicator(Modifier.padding(8.dp))
    error != null -> Text("Search failed: $error", color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
    results?.isEmpty() == true -> Text("No products found. Try a shorter name or the vendor name.", style = MaterialTheme.typography.bodySmall)
  }
  results?.takeIf { it.isNotEmpty() }?.let { list ->
    LazyColumn(Modifier.heightIn(max = 220.dp)) {
      items(list, key = { "${it.vendor}:${it.product}" }) { s ->
        Column(Modifier.fillMaxWidth().clickable { onPick(s) }.padding(vertical = 6.dp)) {
          Text(s.title, style = MaterialTheme.typography.bodyMedium)
          Text("${s.vendor}:${s.product}", style = MaterialTheme.typography.labelSmall, fontFamily = JetBrainsMono, color = MaterialTheme.colorScheme.primary)
        }
      }
    }
  }
}

@Composable
private fun CpeDialog(
  title: String,
  initialQuery: String,
  initialVendor: String,
  initialProduct: String,
  initialVersion: String?,
  search: suspend (String) -> List<CpeSuggestion>,
  onDismiss: () -> Unit,
  onClear: (() -> Unit)?,
  onSave: (String, String, String?) -> Unit,
) {
  var vendor by remember { mutableStateOf(initialVendor) }
  var product by remember { mutableStateOf(initialProduct) }
  var version by remember { mutableStateOf(initialVersion) }
  AlertDialog(
    onDismissRequest = onDismiss,
    title = { Text(title) },
    text = {
      Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        CpeSearch(initialQuery, search) { vendor = it.vendor; product = it.product }
        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
          OutlinedTextField(vendor, { vendor = it }, label = { Text("Vendor") }, singleLine = true, modifier = Modifier.weight(1f))
          OutlinedTextField(product, { product = it }, label = { Text("Product") }, singleLine = true, modifier = Modifier.weight(1f))
        }
        version?.let { v ->
          OutlinedTextField(v, { version = it }, label = { Text("Your version (for the affected check)") }, singleLine = true, modifier = Modifier.fillMaxWidth())
        }
      }
    },
    confirmButton = { Button(onClick = { onSave(vendor, product, version) }, enabled = vendor.isNotBlank() && product.isNotBlank()) { Text("Save & monitor") } },
    dismissButton = {
      Row {
        if (onClear != null) TextButton(onClick = onClear) { Text("Remove") }
        TextButton(onClick = onDismiss) { Text("Cancel") }
      }
    },
  )
}

@Composable
internal fun AddProductDialog(search: suspend (String) -> List<CpeSuggestion>, onDismiss: () -> Unit, onAdd: (String, String, String, String) -> Unit) {
  var vendor by remember { mutableStateOf("") }
  var product by remember { mutableStateOf("") }
  var label by remember { mutableStateOf("") }
  var version by remember { mutableStateOf("") }
  AlertDialog(
    onDismissRequest = onDismiss,
    title = { Text("Add a product") },
    text = {
      Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Text("For software that isn't installed on this phone (for example a desktop app you use).", style = MaterialTheme.typography.bodySmall)
        CpeSearch("", search) { vendor = it.vendor; product = it.product; if (label.isBlank()) label = it.title }
        OutlinedTextField(label, { label = it }, label = { Text("Display name") }, singleLine = true, modifier = Modifier.fillMaxWidth())
        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
          OutlinedTextField(vendor, { vendor = it }, label = { Text("Vendor") }, singleLine = true, modifier = Modifier.weight(1f))
          OutlinedTextField(product, { product = it }, label = { Text("Product") }, singleLine = true, modifier = Modifier.weight(1f))
        }
        OutlinedTextField(version, { version = it }, label = { Text("Your version (optional)") }, singleLine = true, modifier = Modifier.fillMaxWidth())
      }
    },
    confirmButton = { Button(onClick = { onAdd(vendor, product, label, version) }, enabled = vendor.isNotBlank() && product.isNotBlank()) { Text("Add") } },
    dismissButton = { OutlinedButton(onClick = onDismiss) { Text("Cancel") } },
  )
}
