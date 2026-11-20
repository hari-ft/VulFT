package com.vulft.app.ui.search

import com.vulft.app.ui.theme.MonoType
import com.vulft.app.ui.common.outlinedCardBorder
import com.vulft.app.ui.common.outlinedCardColors
import com.vulft.app.ui.common.ExploitedBadge
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
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
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
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.compose.viewModel
import com.vulft.app.container
import com.vulft.app.data.CveEntry
import com.vulft.app.data.Severity
import com.vulft.app.data.remote.CveQuery
import com.vulft.app.ui.common.BackTopBar
import com.vulft.app.ui.common.SeverityBadge
import com.vulft.app.ui.common.pct
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch

data class CveSearchState(
  val query: CveQuery = CveQuery(),
  val results: List<CveEntry> = emptyList(),
  val olderStart: Int? = null,
  val total: Int = 0,
  val loading: Boolean = false,
  val error: String? = null,
  val searched: Boolean = false,
)

class CveSearchViewModel(app: Application) : AndroidViewModel(app) {
  private val repo = app.container.repo
  val state = MutableStateFlow(CveSearchState())
  private var job: Job? = null

  fun search(q: CveQuery) {
    if (q.text.isBlank() && q.severity == null && !q.kevOnly && q.lastDays == null) return
    job?.cancel()
    state.value = CveSearchState(query = q, loading = true, searched = true)
    job = viewModelScope.launch { load(null) }
  }

  fun loadOlder() {
    val s = state.value
    val before = s.olderStart ?: return
    if (s.loading) return
    state.value = s.copy(loading = true)
    job = viewModelScope.launch { load(before) }
  }

  private suspend fun load(before: Int?) {
    val s = state.value
    runCatching { repo.searchAllCves(s.query, before) }
      .onSuccess { p ->
        state.value = s.copy(results = (s.results + p.items).distinctBy { it.id }, olderStart = p.olderStart,
          total = if (before == null) p.total else s.total, loading = false, error = null)
      }
      .onFailure { e ->
        if (e is kotlinx.coroutines.CancellationException) throw e
        val msg = (e as? com.vulft.app.data.remote.HttpException)?.takeIf { it.code == 404 }?.let { "Not found" } ?: (e.message ?: "Search failed")
        state.value = s.copy(loading = false, error = msg)
      }
  }
}

private val dayOptions = listOf(null to "Any time", 7 to "7 days", 30 to "30 days", 120 to "120 days")

@Composable
fun CveSearchScreen(onBack: () -> Unit, onOpenCve: (String) -> Unit, vm: CveSearchViewModel = viewModel()) {
  val s by vm.state.collectAsStateWithLifecycle()
  var text by remember { mutableStateOf(s.query.text) }
  var severity by remember { mutableStateOf(s.query.severity) }
  var kev by remember { mutableStateOf(s.query.kevOnly) }
  var days by remember { mutableStateOf(s.query.lastDays) }
  val query = CveQuery(text, severity, kev, days)
  val canSearch = text.isNotBlank() || severity != null || kev || days != null

  Scaffold(topBar = { BackTopBar("Search all CVEs", onBack) }) { padding ->
    Column(Modifier.padding(padding).fillMaxSize()) {
      Row(Modifier.padding(horizontal = 12.dp, vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
        OutlinedTextField(
          text, { text = it }, singleLine = true, modifier = Modifier.weight(1f),
          placeholder = { Text("CVE-2024-3094, log4j, fortinet vpn…") },
          keyboardOptions = KeyboardOptions(imeAction = ImeAction.Search),
          keyboardActions = KeyboardActions(onSearch = { vm.search(query) }),
        )
        Spacer(Modifier.width(6.dp))
        Button(onClick = { vm.search(query) }, enabled = canSearch && !(s.loading && s.results.isEmpty())) { Text("Search") }
      }
      LazyRow(contentPadding = PaddingValues(horizontal = 12.dp), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
        items(Severity.all.take(4)) { sev ->
          FilterChip(severity == sev, { severity = if (severity == sev) null else sev; vm.search(CveQuery(text, severity, kev, days)) },
            label = { Text(Severity.label(sev)) })
        }
        item { FilterChip(kev, { kev = !kev; vm.search(CveQuery(text, severity, kev, days)) }, label = { Text("Exploited (KEV)") }) }
      }
      LazyRow(contentPadding = PaddingValues(horizontal = 12.dp), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
        items(dayOptions) { (d, label) ->
          FilterChip(days == d, { days = d; vm.search(CveQuery(text, severity, kev, days)) }, label = { Text(if (d == null) label else "Published last $label") })
        }
      }

      if (!s.searched) {
        Text(
          "Searches every published CVE, for any product, not just your apps.\n\n" +
            "• A CVE ID is looked up in NVD, Microsoft MSRC, OSV.dev and CISA KEV, merged into one result\n" +
            "• Words search NVD descriptions, Microsoft CVE titles and the CISA KEV catalog (all words must match)\n" +
            "• Or leave it empty and use the filters, e.g. Critical + Exploited + last 30 days (NVD)\n\n" +
            "EPSS is added to every result; GitHub advisories are on each CVE's page. Open-source packages are searched by name in Browse all products → OSV.",
          style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(16.dp),
        )
      }
      s.error?.let { Text(it, color = MaterialTheme.colorScheme.error, modifier = Modifier.padding(16.dp)) }
      if (s.searched && !s.loading && s.results.isEmpty() && s.error == null) Text("No CVEs found.", Modifier.padding(16.dp))
      if (s.results.isNotEmpty()) {
        Text("${s.total} CVEs · newest first · showing ${s.results.size}", style = MaterialTheme.typography.labelSmall,
          color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp))
      }
      LazyColumn(Modifier.weight(1f), contentPadding = PaddingValues(start = 12.dp, end = 12.dp, bottom = 24.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        items(s.results, key = { it.id }) { c -> ResultCard(c) { onOpenCve(c.id) } }
        item {
          when {
            s.loading -> Row(Modifier.fillMaxWidth().padding(16.dp), horizontalArrangement = Arrangement.Center) { CircularProgressIndicator() }
            s.olderStart != null -> Row(Modifier.fillMaxWidth().padding(8.dp), horizontalArrangement = Arrangement.Center) {
              OutlinedButton(onClick = vm::loadOlder) { Text("Load older") }
            }
          }
        }
      }
    }
  }
}

@Composable
private fun ResultCard(c: CveEntry, onClick: () -> Unit) {
  Card(Modifier.fillMaxWidth().clickable(onClick = onClick), shape = MaterialTheme.shapes.medium, colors = outlinedCardColors(), border = outlinedCardBorder()) {
    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
      Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
        Text(c.id, style = MonoType.large, maxLines = 1, modifier = Modifier.weight(1f))
        SeverityBadge(c.severity, c.cvssScore)
      }
      if (c.exploited) ExploitedBadge()
      val products = c.affectedProducts.split(",").filter { it.isNotBlank() }.map { k ->
        when {
          k.startsWith("osv:") -> k.removePrefix("osv:").replaceFirst(':', ' ')
          k.startsWith("msrc:") -> k.removePrefix("msrc:")
          else -> k
        }
      }
      if (products.isNotEmpty()) {
        Text(products.take(3).joinToString(" · ") + if (products.size > 3) " +${products.size - 3}" else "",
          style = MonoType.medium, color = MaterialTheme.colorScheme.primary, maxLines = 1, overflow = TextOverflow.Ellipsis)
      }
      Text(c.description, style = MaterialTheme.typography.bodyMedium, maxLines = 3, overflow = TextOverflow.Ellipsis)
      // Which databases this result came from.
      val srcs = (c.sourceList() + listOfNotNull("CISA KEV".takeIf { c.kev }, "EPSS".takeIf { c.epss != null })).distinct()
      Text("${c.published.take(10)} · EPSS ${pct(c.epss)} · " + srcs.joinToString(" + "), style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
  }
}
