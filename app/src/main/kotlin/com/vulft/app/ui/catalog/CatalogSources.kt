package com.vulft.app.ui.catalog

import android.app.Application
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.ArrowDropDown
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.compose.viewModel
import com.vulft.app.SyncScheduler
import com.vulft.app.container
import com.vulft.app.data.remote.MsrcProduct
import com.vulft.app.data.remote.OsvClient
import com.vulft.app.ui.common.SectionCard
import com.vulft.app.ui.theme.MonoType
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch

sealed interface OsvCheck {
  data object Idle : OsvCheck
  data object Checking : OsvCheck
  data class Result(val total: Int, val affecting: Int?) : OsvCheck
  data class Error(val msg: String) : OsvCheck
}

data class MsrcSearch(val loading: Boolean = false, val results: List<MsrcProduct> = emptyList(), val error: String? = null, val searched: Boolean = false)

class SourceCatalogViewModel(app: Application) : AndroidViewModel(app) {
  private val repo = app.container.repo
  val osv = MutableStateFlow<OsvCheck>(OsvCheck.Idle)
  val msrc = MutableStateFlow(MsrcSearch())
  val message = MutableStateFlow<String?>(null)

  fun checkOsv(eco: String, name: String, version: String) = viewModelScope.launch {
    osv.value = OsvCheck.Checking
    osv.value = runCatching { repo.checkOsvPackage(eco, name.trim(), version.trim()) }
      .fold({ OsvCheck.Result(it.first, it.second) }, { OsvCheck.Error(it.message ?: "Lookup failed") })
  }

  fun monitorOsv(eco: String, name: String, version: String) = viewModelScope.launch {
    repo.addSourceProduct("osv:$eco", name.trim(), "${name.trim()} ($eco)", version)
    SyncScheduler.runNow(getApplication())
    message.value = "Monitoring ${name.trim()} – syncing now"
    osv.value = OsvCheck.Idle
  }

  fun searchMsrc(text: String) = viewModelScope.launch {
    if (text.isBlank()) return@launch
    msrc.value = MsrcSearch(loading = true, searched = true)
    msrc.value = runCatching { repo.searchMicrosoftProducts(text) }
      .fold({ MsrcSearch(results = it, searched = true) }, { MsrcSearch(error = it.message ?: "Search failed", searched = true) })
  }

  fun monitorMsrc(products: List<MsrcProduct>) = viewModelScope.launch {
    products.forEach { repo.addSourceProduct("msrc", it.name, it.name, null) }
    SyncScheduler.runNow(getApplication())
    message.value = "Monitoring ${products.size} Microsoft products – syncing now"
  }
}

/** Track any open-source package OSV.dev knows (PyPI, npm, Maven, Go, NuGet, crates.io, …). */
@Composable
fun OsvTab(tracked: Set<String>, vm: SourceCatalogViewModel = viewModel()) {
  val check by vm.osv.collectAsStateWithLifecycle()
  val message by vm.message.collectAsStateWithLifecycle()
  var eco by remember { mutableStateOf("PyPI") }
  var name by remember { mutableStateOf("") }
  var version by remember { mutableStateOf("") }
  var menu by remember { mutableStateOf(false) }
  val key = "osv:$eco:${name.trim()}"

  Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
    Text("Track an open-source package or library. OSV.dev gives exact fixed versions, so the \"affected\" check is precise.",
      style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
    SectionCard("Package") {
      Box {
        OutlinedButton(onClick = { menu = true }, modifier = Modifier.fillMaxWidth()) {
          Text("Ecosystem: $eco", modifier = Modifier.weight(1f)); Icon(Icons.Outlined.ArrowDropDown, null)
        }
        DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
          OsvClient.ecosystems.forEach { e -> DropdownMenuItem(text = { Text(e) }, onClick = { eco = e; menu = false; vm.osv.value = OsvCheck.Idle }) }
        }
      }
      OutlinedTextField(name, { name = it; vm.osv.value = OsvCheck.Idle }, label = { Text("Package name (exact)") }, singleLine = true,
        placeholder = { Text(when (eco) { "Maven" -> "org.apache.logging.log4j:log4j-core"; "Go" -> "golang.org/x/net"; "npm" -> "lodash"; else -> "django" }) },
        modifier = Modifier.fillMaxWidth())
      OutlinedTextField(version, { version = it; vm.osv.value = OsvCheck.Idle }, label = { Text("Your version (optional, recommended)") }, singleLine = true,
        modifier = Modifier.fillMaxWidth(), keyboardOptions = KeyboardOptions(imeAction = ImeAction.Done),
        keyboardActions = KeyboardActions(onDone = { if (name.isNotBlank()) vm.checkOsv(eco, name, version) }))
      Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
        OutlinedButton(onClick = { vm.checkOsv(eco, name, version) }, enabled = name.isNotBlank() && check != OsvCheck.Checking) { Text("Check") }
        Button(onClick = { vm.monitorOsv(eco, name, version) }, enabled = name.isNotBlank() && key !in tracked) { Text(if (key in tracked) "Monitoring" else "Monitor") }
      }
      when (val c = check) {
        OsvCheck.Idle -> {}
        OsvCheck.Checking -> CircularProgressIndicator()
        is OsvCheck.Error -> Text(c.msg, color = MaterialTheme.colorScheme.error)
        is OsvCheck.Result -> Text(
          if (c.total == 0) "OSV has no vulnerabilities for \"$name\" in $eco. Check the exact name."
          else "${c.total} known vulnerabilities" + (c.affecting?.let { " · $it affect version $version" } ?: " · add your version to see which affect you"),
          style = MaterialTheme.typography.titleSmall)
      }
      message?.let { Text(it, color = MaterialTheme.colorScheme.primary) }
    }
    Text("Your phone's own Android OS is checked automatically (Settings → Apps on this device).",
      style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
  }
}

/** Track Microsoft products from the Security Update Guide (Windows, Office, Edge, Teams, .NET, Android apps…). */
@Composable
fun MsrcTab(tracked: Set<String>, vm: SourceCatalogViewModel = viewModel()) {
  val s by vm.msrc.collectAsStateWithLifecycle()
  val message by vm.message.collectAsStateWithLifecycle()
  var text by remember { mutableStateOf("") }
  var selected by remember { mutableStateOf(setOf<String>()) }

  Column(Modifier.fillMaxSize()) {
    Row(Modifier.padding(horizontal = 12.dp, vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
      OutlinedTextField(text, { text = it }, singleLine = true, modifier = Modifier.weight(1f),
        placeholder = { Text("Office, Windows 11, Edge, Teams, .NET…") },
        keyboardOptions = KeyboardOptions(imeAction = ImeAction.Search), keyboardActions = KeyboardActions(onSearch = { vm.searchMsrc(text) }))
      Spacer(Modifier.width(6.dp))
      Button(onClick = { vm.searchMsrc(text) }, enabled = text.isNotBlank() && !s.loading) { Text("Search") }
    }
    if (!s.searched) {
      Text("Microsoft's own CVE data, with the KB update and fixed build number for each product. Add your build number later to see whether it's patched.",
        style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(16.dp))
    }
    s.error?.let { Text(it, color = MaterialTheme.colorScheme.error, modifier = Modifier.padding(16.dp)) }
    message?.let { Text(it, color = MaterialTheme.colorScheme.primary, modifier = Modifier.padding(horizontal = 16.dp)) }
    if (s.loading) Row(Modifier.fillMaxWidth().padding(24.dp), horizontalArrangement = Arrangement.Center) { CircularProgressIndicator() }
    if (s.searched && !s.loading && s.results.isEmpty() && s.error == null) {
      Text("No Microsoft products found in the last year. Names are case-sensitive, e.g. \"Office\", \"Windows 11\".", Modifier.padding(16.dp))
    }
    LazyColumn(Modifier.weight(1f), contentPadding = PaddingValues(bottom = 16.dp)) {
      items(s.results, key = { it.name }) { p ->
        val isTracked = "msrc:${p.name}" in tracked
        Row(Modifier.fillMaxWidth().clickable(enabled = !isTracked) { selected = if (p.name in selected) selected - p.name else selected + p.name }
          .padding(horizontal = 8.dp, vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
          Checkbox(checked = isTracked || p.name in selected, onCheckedChange = { selected = if (p.name in selected) selected - p.name else selected + p.name }, enabled = !isTracked)
          Column(Modifier.weight(1f)) {
            Text(p.name, style = MaterialTheme.typography.titleSmall)
            Text(p.family + if (isTracked) " · Monitoring" else "", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
          }
        }
        HorizontalDivider()
      }
    }
    // Same bottom bar as the NVD and CISA KEV tabs.
    if (selected.isNotEmpty()) {
      androidx.compose.material3.BottomAppBar {
        androidx.compose.material3.TextButton(onClick = { selected = emptySet() }) { Text("Clear") }
        Spacer(Modifier.weight(1f))
        Button(onClick = { vm.monitorMsrc(s.results.filter { it.name in selected }); selected = emptySet() },
          modifier = Modifier.padding(end = 12.dp)) { Text("Monitor ${selected.size} selected") }
      }
    }
  }
}

/** Monospace product key line used in a few places. */
@Composable
fun ProductKeyText(text: String) = Text(text, style = MonoType.small, color = MaterialTheme.colorScheme.primary)
