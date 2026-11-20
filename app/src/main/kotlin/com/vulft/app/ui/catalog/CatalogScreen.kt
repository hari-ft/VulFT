package com.vulft.app.ui.catalog

import androidx.compose.runtime.mutableIntStateOf
import com.vulft.app.ui.theme.MonoType
import com.vulft.app.ui.common.RansomwareBadge
import android.app.Application
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material3.AssistChip
import androidx.compose.material3.BottomAppBar
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.PrimaryTabRow
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.compose.viewModel
import com.vulft.app.container
import com.vulft.app.data.cpeKey
import com.vulft.app.data.remote.CpeSuggestion
import com.vulft.app.data.remote.KevProduct
import com.vulft.app.ui.apps.AddProductDialog
import com.vulft.app.ui.common.BackTopBar
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

data class SearchState(
  val keyword: String = "",
  val vendor: String? = null,
  val results: List<CpeSuggestion> = emptyList(),
  val nextStart: Int? = null,
  val total: Int = 0,
  val loading: Boolean = false,
  val error: String? = null,
  val searched: Boolean = false,
)

class CatalogViewModel(app: Application) : AndroidViewModel(app) {
  private val repo = app.container.repo
  val search = MutableStateFlow(SearchState())
  val kevFilter = MutableStateFlow("")
  private val kevAll = MutableStateFlow<List<KevProduct>?>(null)
  val kevError = MutableStateFlow<String?>(null)
  val selectedSearch = MutableStateFlow<Map<String, CpeSuggestion>>(emptyMap())
  val selectedKev = MutableStateFlow<Map<String, KevProduct>>(emptyMap())
  val adding = MutableStateFlow<String?>(null)
  val message = MutableStateFlow<String?>(null)

  /** vendor:product keys already being monitored. */
  val tracked = repo.apps.map { list -> list.filter { it.watched }.mapNotNull { it.cpeKey() }.toSet() }
    .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptySet())

  val kevVisible = combine(kevAll, kevFilter) { all, q ->
    all?.filter { q.isBlank() || it.vendor.contains(q, true) || it.product.contains(q, true) }
  }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), null)

  fun runSearch(keyword: String = search.value.keyword, vendor: String? = null) {
    if (keyword.isBlank()) return
    search.value = SearchState(keyword = keyword, vendor = vendor, loading = true, searched = true)
    loadPage(0)
  }

  fun loadMore() { search.value.nextStart?.let { search.value = search.value.copy(loading = true); loadPage(it) } }

  private fun loadPage(start: Int) = viewModelScope.launch {
    val s = search.value
    runCatching { repo.searchCatalog(s.keyword, start, s.vendor) }
      .onSuccess { page ->
        val merged = (s.results + page.items).distinctBy { it.key }
        search.value = s.copy(results = merged, nextStart = page.nextStart, total = page.total, loading = false, error = null)
      }
      .onFailure { search.value = s.copy(loading = false, error = it.message ?: "Search failed") }
  }

  fun browseVendor(vendor: String) = runSearch(vendor.replace('_', ' '), vendor)

  fun loadKev() {
    if (kevAll.value != null) return
    viewModelScope.launch {
      kevError.value = null
      runCatching { repo.kevProducts() }.onSuccess { kevAll.value = it }.onFailure { kevError.value = it.message }
    }
  }

  fun toggle(s: CpeSuggestion) = selectedSearch.value.let { m -> selectedSearch.value = if (s.key in m) m - s.key else m + (s.key to s) }
  fun toggle(k: KevProduct) = selectedKev.value.let { m -> selectedKev.value = if (k.key in m) m - k.key else m + (k.key to k) }
  fun clearSelection() { selectedSearch.value = emptyMap(); selectedKev.value = emptyMap() }

  fun addSelected() = viewModelScope.launch {
    val direct = selectedSearch.value.values.toList()
    val kev = selectedKev.value.values.toList()
    val failed = mutableListOf<String>()
    val resolved = mutableListOf<CpeSuggestion>()
    kev.forEachIndexed { i, k ->
      adding.value = "Finding NVD product ${i + 1}/${kev.size}: ${k.vendor} ${k.product}"
      runCatching { repo.resolveKev(k) }.getOrNull()?.let(resolved::add) ?: failed.add("${k.vendor} ${k.product}")
    }
    adding.value = "Adding…"
    repo.addProducts((direct + resolved).distinctBy { it.key })
    adding.value = null
    clearSelection()
    val added = (direct + resolved).distinctBy { it.key }.size
    message.value = "Added $added products. Sync to download their CVEs." +
      if (failed.isNotEmpty()) " Couldn't match: ${failed.joinToString()} – search for them in 'All NVD products'." else ""
  }

  fun addManual(vendor: String, product: String, label: String, version: String) = viewModelScope.launch {
    repo.addManualProduct(vendor, product, label, version); message.value = "Added $label"
  }

  suspend fun quickSearch(q: String) = repo.searchCatalog(q, 0, null).items
}

@Composable
fun CatalogScreen(onBack: () -> Unit, vm: CatalogViewModel = viewModel()) {
  var tab by remember { mutableIntStateOf(0) }
  var manual by remember { mutableStateOf(false) }
  val selS by vm.selectedSearch.collectAsStateWithLifecycle()
  val selK by vm.selectedKev.collectAsStateWithLifecycle()
  val adding by vm.adding.collectAsStateWithLifecycle()
  val message by vm.message.collectAsStateWithLifecycle()
  val tracked by vm.tracked.collectAsStateWithLifecycle()
  val snackbar = remember { SnackbarHostState() }
  LaunchedEffect(message) { message?.let { snackbar.showSnackbar(it); vm.message.value = null } }
  val count = selS.size + selK.size

  Scaffold(
    topBar = {
      BackTopBar("Product catalog", onBack) {
        IconButton(onClick = { manual = true }) { Icon(Icons.Default.Edit, "Enter product manually") }
      }
    },
    snackbarHost = { SnackbarHost(snackbar) },
    bottomBar = {
      if (count > 0 || adding != null) {
        BottomAppBar {
          if (adding != null) {
            Column(Modifier.padding(horizontal = 16.dp)) { Text(adding!!, style = MaterialTheme.typography.bodySmall); LinearProgressIndicator(Modifier.fillMaxWidth()) }
          } else {
            TextButton(onClick = vm::clearSelection) { Text("Clear") }
            Spacer(Modifier.weight(1f))
            Button(onClick = vm::addSelected, modifier = Modifier.padding(end = 12.dp)) { Text("Monitor $count selected") }
          }
        }
      }
    },
  ) { padding ->
    Column(Modifier.padding(padding).fillMaxSize()) {
      androidx.compose.material3.PrimaryScrollableTabRow(selectedTabIndex = tab, edgePadding = 8.dp) {
        Tab(tab == 0, { tab = 0 }, text = { Text("NVD products") })
        Tab(tab == 1, { tab = 1; vm.loadKev() }, text = { Text("Exploited (CISA KEV)") })
        Tab(tab == 2, { tab = 2 }, text = { Text("Open source (OSV)") })
        Tab(tab == 3, { tab = 3 }, text = { Text("Microsoft (MSRC)") })
      }
      when (tab) {
        0 -> SearchTab(vm, selS, tracked)
        1 -> KevTab(vm, selK, tracked)
        2 -> OsvTab(tracked)
        else -> MsrcTab(tracked)
      }
    }
  }

  if (manual) {
    AddProductDialog(search = vm::quickSearch, onDismiss = { manual = false }) { v, p, label, version -> vm.addManual(v, p, label, version); manual = false }
  }
}

@Composable
private fun SearchTab(vm: CatalogViewModel, selected: Map<String, CpeSuggestion>, tracked: Set<String>) {
  val s by vm.search.collectAsStateWithLifecycle()
  var text by remember { mutableStateOf(s.keyword) }
  Column(Modifier.fillMaxSize()) {
    Row(Modifier.padding(horizontal = 12.dp, vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
      OutlinedTextField(
        text, { text = it }, singleLine = true, modifier = Modifier.weight(1f),
        placeholder = { Text("Any product or vendor, e.g. windows, fortinet, wordpress") },
        keyboardOptions = KeyboardOptions(imeAction = ImeAction.Search),
        keyboardActions = KeyboardActions(onSearch = { vm.runSearch(text) }),
      )
      Spacer(Modifier.width(6.dp))
      Button(onClick = { vm.runSearch(text) }, enabled = text.isNotBlank() && !s.loading) { Text("Search") }
    }
    s.vendor?.let { v ->
      Row(Modifier.padding(horizontal = 12.dp), verticalAlignment = Alignment.CenterVertically) {
        AssistChip(onClick = { vm.runSearch(text) }, label = { Text("Vendor: $v") }, trailingIcon = { Icon(Icons.Default.Close, "Clear vendor", Modifier.padding(2.dp)) })
      }
    }
    if (!s.searched) {
      Text(
        "Search all ~1.5 million entries NVD publishes: apps, operating systems, routers, libraries, desktop software. " +
          "Tap a vendor name to list all of that vendor's products. Tick any number of results and tap Monitor.",
        style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(16.dp),
      )
    }
    s.error?.let { Text(it, color = MaterialTheme.colorScheme.error, modifier = Modifier.padding(16.dp)) }
    if (s.searched && !s.loading && s.results.isEmpty() && s.error == null) Text("No products found.", Modifier.padding(16.dp))
    if (s.results.isNotEmpty()) {
      Text("${s.results.size} products from ${minOf(s.nextStart ?: s.total, s.total)} of ${s.total} NVD entries",
        style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(horizontal = 16.dp))
    }
    LazyColumn(Modifier.weight(1f), contentPadding = PaddingValues(bottom = 16.dp)) {
      items(s.results, key = { it.key }) { r ->
        val isTracked = r.key in tracked
        Row(Modifier.fillMaxWidth().clickable(enabled = !isTracked) { vm.toggle(r) }.padding(horizontal = 8.dp, vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
          Checkbox(checked = isTracked || r.key in selected, onCheckedChange = { vm.toggle(r) }, enabled = !isTracked)
          Column(Modifier.weight(1f)) {
            Text(r.title, fontWeight = FontWeight.SemiBold)
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
              Text(r.key, style = MonoType.medium, color = MaterialTheme.colorScheme.primary)
              Text(r.partLabel, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
              if (isTracked) Text("Monitoring", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.tertiary)
            }
          }
          if (s.vendor == null) TextButton(onClick = { text = r.vendor.replace('_', ' '); vm.browseVendor(r.vendor) }) { Text("All ${r.vendor}") }
        }
        HorizontalDivider()
      }
      item {
        when {
          s.loading -> Row(Modifier.fillMaxWidth().padding(16.dp), horizontalArrangement = Arrangement.Center) { CircularProgressIndicator() }
          s.nextStart != null -> Row(Modifier.fillMaxWidth().padding(12.dp), horizontalArrangement = Arrangement.Center) {
            OutlinedButton(onClick = vm::loadMore) { Text("Load more") }
          }
        }
      }
    }
  }
}

@Composable
private fun KevTab(vm: CatalogViewModel, selected: Map<String, KevProduct>, tracked: Set<String>) {
  val list by vm.kevVisible.collectAsStateWithLifecycle()
  val q by vm.kevFilter.collectAsStateWithLifecycle()
  val err by vm.kevError.collectAsStateWithLifecycle()
  LaunchedEffect(Unit) { vm.loadKev() }
  Column(Modifier.fillMaxSize()) {
    OutlinedTextField(q, { vm.kevFilter.value = it }, singleLine = true, placeholder = { Text("Filter vendor or product") },
      modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 6.dp))
    Text("Every product CISA has seen attacked in the wild, most-exploited first.", style = MaterialTheme.typography.bodySmall,
      color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(horizontal = 16.dp))
    err?.let { Text("Couldn't load: $it", color = MaterialTheme.colorScheme.error, modifier = Modifier.padding(16.dp)) }
    val l = list
    if (l == null && err == null) {
      Row(Modifier.fillMaxWidth().padding(24.dp), horizontalArrangement = Arrangement.Center) { CircularProgressIndicator() }
    } else if (l != null) {
      Text("${l.size} products", style = MaterialTheme.typography.labelSmall, modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp))
      LazyColumn(Modifier.weight(1f)) {
        items(l, key = { it.key }) { k ->
          val norm = "${k.vendor}:${k.product}".lowercase().replace(' ', '_')
          val isTracked = norm in tracked
          Row(Modifier.fillMaxWidth().clickable { vm.toggle(k) }.padding(horizontal = 8.dp, vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
            Checkbox(checked = isTracked || k.key in selected, onCheckedChange = { vm.toggle(k) }, enabled = !isTracked)
            Column(Modifier.weight(1f)) {
              Text("${k.vendor} ${k.product}", fontWeight = FontWeight.SemiBold)
              Text("${k.count} exploited CVEs · latest added ${k.latest}", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            if (k.ransomware) RansomwareBadge()
          }
          HorizontalDivider()
        }
      }
    }
  }
}
