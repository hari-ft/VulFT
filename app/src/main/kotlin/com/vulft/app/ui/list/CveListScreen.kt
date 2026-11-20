package com.vulft.app.ui.list

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.Send
import androidx.compose.material.icons.automirrored.outlined.Sort
import androidx.compose.material.icons.outlined.AddBox
import androidx.compose.material.icons.outlined.ArrowDropDown
import androidx.compose.material.icons.outlined.Check
import androidx.compose.material.icons.outlined.Checklist
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material.icons.outlined.FilterAltOff
import androidx.compose.material.icons.outlined.MoreVert
import androidx.compose.material.icons.outlined.Search
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material.icons.outlined.Sync
import androidx.compose.material.icons.outlined.TravelExplore
import androidx.compose.material.icons.outlined.Upload
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.vulft.app.data.Severity
import com.vulft.app.data.VulnItem
import com.vulft.app.ui.common.EmptyState
import com.vulft.app.ui.common.ExploitedBadge
import com.vulft.app.ui.common.SeverityBadge
import com.vulft.app.ui.common.VersionStatus
import com.vulft.app.ui.common.outlinedCardBorder
import com.vulft.app.ui.common.pct
import com.vulft.app.ui.theme.MonoType
import com.vulft.app.ui.theme.Vulft
import com.vulft.app.ui.common.UpdatedBadge
import com.vulft.app.ui.common.SeverityBars
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.material.icons.outlined.LocalFireDepartment
import androidx.compose.material3.Switch
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CveListScreen(
  onOpenCve: (String) -> Unit,
  onOpenSettings: () -> Unit,
  onOpenApps: () -> Unit,
  onOpenSearch: () -> Unit,
  onOpenCatalog: () -> Unit,
  vm: CveListViewModel = viewModel(),
) {
  val visible by vm.visible.collectAsStateWithLifecycle()
  val selected by vm.selected.collectAsStateWithLifecycle()
  val sort by vm.sort.collectAsStateWithLifecycle()
  val filter by vm.filter.collectAsStateWithLifecycle()
  val appOptions by vm.appOptions.collectAsStateWithLifecycle()
  val total by vm.totalCount.collectAsStateWithLifecycle()
  val watched by vm.watchedCount.collectAsStateWithLifecycle()
  val progress by vm.syncProgress.collectAsStateWithLifecycle()
  val settings by vm.settings.collectAsStateWithLifecycle()
  val message by vm.message.collectAsStateWithLifecycle()

  var moreMenu by remember { mutableStateOf(false) }
  var sortMenu by remember { mutableStateOf(false) }
  var exportDialog by remember { mutableStateOf(false) }
  var showSearch by remember { mutableStateOf(false) }
  val snackbar = remember { SnackbarHostState() }

  val csvLauncher = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("text/csv")) { uri -> uri?.let { vm.export(it, json = false) } }
  val jsonLauncher = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/json")) { uri -> uri?.let { vm.export(it, json = true) } }

  LaunchedEffect(message) { message?.let { snackbar.showSnackbar(it); vm.message.value = null } }

  Scaffold(
    snackbarHost = { SnackbarHost(snackbar) },
    topBar = {
      if (selected.isNotEmpty()) {
        TopAppBar(
          title = { Text("${selected.size} selected") },
          navigationIcon = { IconButton(onClick = vm::clearSelection) { Icon(Icons.Outlined.Close, "Clear selection") } },
          actions = {
            TextButton(onClick = vm::selectAllVisible) { Text("Select all") }
            IconButton(onClick = { exportDialog = true }) { Icon(Icons.Outlined.Upload, "Export") }
            IconButton(onClick = vm::email) { Icon(Icons.AutoMirrored.Outlined.Send, "Email") }
          },
        )
      } else {
        TopAppBar(
          title = { Text("CVEs", maxLines = 1) },
          actions = {
            IconButton(onClick = { showSearch = !showSearch }) { Icon(Icons.Outlined.Search, "Search") }
            Box {
              IconButton(onClick = { sortMenu = true }) { Icon(Icons.AutoMirrored.Outlined.Sort, "Sort") }
              DropdownMenu(expanded = sortMenu, onDismissRequest = { sortMenu = false }) {
                SortOrder.entries.forEach { o ->
                  DropdownMenuItem(
                    text = { Text(o.label) },
                    leadingIcon = { if (o == sort) Icon(Icons.Outlined.Check, null) else Spacer(Modifier.size(24.dp)) },
                    onClick = { vm.sort.value = o; sortMenu = false },
                  )
                }
              }
            }
            IconButton(onClick = { exportDialog = true }) { Icon(Icons.Outlined.Upload, "Export") }
            IconButton(onClick = vm::syncNow, enabled = progress == null) { Icon(Icons.Outlined.Sync, "Sync now") }
            Box {
              IconButton(onClick = { moreMenu = true }) { Icon(Icons.Outlined.MoreVert, "More") }
              DropdownMenu(expanded = moreMenu, onDismissRequest = { moreMenu = false }) {
                DropdownMenuItem(text = { Text("Search all CVEs") }, leadingIcon = { Icon(Icons.Outlined.TravelExplore, null) },
                  onClick = { moreMenu = false; onOpenSearch() })
                DropdownMenuItem(text = { Text("Browse all products") }, leadingIcon = { Icon(Icons.Outlined.AddBox, null) },
                  onClick = { moreMenu = false; onOpenCatalog() })
                DropdownMenuItem(text = { Text("Apps to monitor") }, leadingIcon = { Icon(Icons.Outlined.Checklist, null) },
                  onClick = { moreMenu = false; onOpenApps() })
                DropdownMenuItem(text = { Text("Settings") }, leadingIcon = { Icon(Icons.Outlined.Settings, null) },
                  onClick = { moreMenu = false; onOpenSettings() })
              }
            }
          },
        )
      }
    },
  ) { padding ->
    Column(Modifier.padding(padding).fillMaxSize()) {
      progress?.let {
        LinearProgressIndicator(Modifier.fillMaxWidth())
        Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
          modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp))
      }
      if (showSearch) {
        OutlinedTextField(
          value = filter.query,
          onValueChange = { q -> vm.filter.value = filter.copy(query = q) },
          placeholder = { Text("Search CVE ID, app or description") },
          leadingIcon = { Icon(Icons.Outlined.Search, null) },
          singleLine = true,
          modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 4.dp),
        )
      }
      val updatedCount by vm.updatedCount.collectAsStateWithLifecycle()
      FilterRow(filter, appOptions, updatedCount, onChange = { vm.filter.value = it })
      Text(
        "${visible?.size ?: 0} of $total · sorted by ${sort.label.lowercase()} · last sync ${com.vulft.app.formatTime(settings.lastSync)}",
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.padding(start = 16.dp, end = 16.dp, top = 8.dp),
      )
      val hidden by vm.hiddenNotAffected.collectAsStateWithLifecycle()
      // Only once the list has loaded (it used to say "0 hidden" while still loading).
      if (visible != null && (settings.showNotAffected || hidden > 0)) Row(Modifier.padding(horizontal = 16.dp), verticalAlignment = Alignment.CenterVertically) {
        Text(
          if (settings.showNotAffected) "Showing CVEs that don't affect your installed version"
          else "$hidden hidden: they don't affect your installed version",
          style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.weight(1f),
        )
        if (settings.showNotAffected || hidden > 0) {
          TextButton(onClick = { vm.setShowNotAffected(!settings.showNotAffected) }) { Text(if (settings.showNotAffected) "Hide" else "Show") }
        }
      }

      val list = visible
      when {
        list == null -> Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) { CircularProgressIndicator() }
        watched == 0 -> EmptyState(Icons.Outlined.Checklist, "No apps monitored yet", "Pick the apps you want VulFT to watch.",
          "Choose apps", onOpenApps, "Or search all CVEs", onOpenSearch)
        total == 0 && progress != null -> EmptyState(Icons.Outlined.Sync, "Syncing…", "Downloading vulnerability data for your $watched monitored apps.")
        total == 0 -> EmptyState(Icons.Outlined.Sync, "No data yet", "Sync to download CVEs for your $watched monitored apps.", "Sync now", vm::syncNow)
        list.isEmpty() && filter.kevOnly && filter == ListFilter(kevOnly = true, query = filter.query) ->
          EmptyState(Icons.Outlined.LocalFireDepartment, "No actively exploited CVEs",
            "None of the CVEs in your monitored apps and products is known to be exploited right now.",
            "Show all CVEs", { vm.filter.value = filter.copy(kevOnly = false) })
        list.isEmpty() -> EmptyState(Icons.Outlined.FilterAltOff, "No CVEs match", "Nothing matches the current filters.", "Clear filters", { vm.filter.value = ListFilter() })
        else -> LazyColumn(contentPadding = PaddingValues(start = 16.dp, end = 16.dp, bottom = 24.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
          items(list, key = { it.key }) { item ->
            CveCard(
              item = item,
              selected = item.key in selected,
              selectionMode = selected.isNotEmpty(),
              onClick = { if (selected.isNotEmpty()) vm.toggleSelect(item.key) else onOpenCve(item.cve.id) },
              onLongClick = { vm.toggleSelect(item.key) },
            )
          }
        }
      }
    }
  }

  if (exportDialog) {
    var json by remember { mutableStateOf(false) }
    val count = vm.exportCount()
    AlertDialog(
      onDismissRequest = { exportDialog = false },
      title = { Text("Export $count CVEs") },
      text = {
        Column {
          Text(if (selected.isEmpty()) "Exports everything in the current filtered list. Long-press CVEs to pick specific ones." else "Exports the selected CVEs.",
            style = MaterialTheme.typography.bodyMedium)
          Spacer(Modifier.size(8.dp))
          Row(verticalAlignment = Alignment.CenterVertically) { RadioButton(!json, { json = false }); Text("CSV (Excel / Sheets)") }
          Row(verticalAlignment = Alignment.CenterVertically) { RadioButton(json, { json = true }); Text("JSON") }
        }
      },
      confirmButton = {
        Button(onClick = {
          exportDialog = false
          val name = "vulft-cves-${java.time.LocalDate.now()}"
          if (json) jsonLauncher.launch("$name.json") else csvLauncher.launch("$name.csv")
        }) { Text("Save file") }
      },
      dismissButton = { TextButton(onClick = { exportDialog = false; vm.email() }) { Text("Email instead") } },
    )
  }
}

@Composable
fun SelectableChip(selected: Boolean, label: String, onClick: () -> Unit, trailing: Boolean = false) {
  FilterChip(
    selected = selected,
    onClick = onClick,
    label = { Text(label) },
    leadingIcon = if (selected) ({ Icon(Icons.Outlined.Check, null, Modifier.size(FilterChipDefaults.IconSize)) }) else null,
    trailingIcon = if (trailing) ({ Icon(Icons.Outlined.ArrowDropDown, null, Modifier.size(FilterChipDefaults.IconSize)) }) else null,
  )
}

/**
 * Filter row, in order: Exploited-only switch (on by default) · Severity ▾ · Apps ▾ · Updated (only when there are updates).
 */
@Composable
private fun FilterRow(filter: ListFilter, apps: List<AppOption>, updatedCount: Int, onChange: (ListFilter) -> Unit) {
  var appMenu by remember { mutableStateOf(false) }
  var sevMenu by remember { mutableStateOf(false) }
  LazyRow(contentPadding = PaddingValues(horizontal = 16.dp), horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
    // 1. Exploited only (default). Turn off to also see CVEs nobody is known to exploit yet.
    item {
      Row(
        Modifier.clip(MaterialTheme.shapes.small)
          .background(if (filter.kevOnly) MaterialTheme.colorScheme.secondaryContainer else MaterialTheme.colorScheme.surfaceContainerHigh)
          .clickable { onChange(filter.copy(kevOnly = !filter.kevOnly)) }
          .padding(start = 12.dp, end = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
      ) {
        Icon(Icons.Outlined.LocalFireDepartment, null, Modifier.size(18.dp))
        Spacer(Modifier.width(6.dp))
        Text("Exploited only", style = MaterialTheme.typography.labelLarge)
        Switch(checked = filter.kevOnly, onCheckedChange = { onChange(filter.copy(kevOnly = it)) }, modifier = Modifier.scale(0.7f))
      }
    }
    // 2. Severity ▾ (multi-select)
    item {
      Box {
        val label = when (filter.severities.size) {
          0 -> "Severity"
          1 -> Severity.label(filter.severities.first())
          else -> "${filter.severities.size} severities"
        }
        SelectableChip(filter.severities.isNotEmpty(), label, { sevMenu = true }, trailing = true)
        DropdownMenu(expanded = sevMenu, onDismissRequest = { sevMenu = false }) {
          DropdownMenuItem(text = { Text("All severities") }, onClick = { onChange(filter.copy(severities = emptySet())); sevMenu = false })
          Severity.all.forEach { s ->
            val on = s in filter.severities
            DropdownMenuItem(
              text = { Row(verticalAlignment = Alignment.CenterVertically) { SeverityBars(s, severityColorFor(s)); Spacer(Modifier.width(8.dp)); Text(Severity.label(s)) } },
              leadingIcon = { Checkbox(checked = on, onCheckedChange = null) },
              onClick = { onChange(filter.copy(severities = if (on) filter.severities - s else filter.severities + s)) },
            )
          }
        }
      }
    }
    // 3. Apps ▾
    item {
      Box {
        SelectableChip(filter.packages.isNotEmpty(), if (filter.packages.isEmpty()) "All apps" else "${filter.packages.size} apps", { appMenu = true }, trailing = true)
        DropdownMenu(expanded = appMenu, onDismissRequest = { appMenu = false }) {
          DropdownMenuItem(text = { Text("All apps") }, onClick = { onChange(filter.copy(packages = emptySet())); appMenu = false })
          apps.forEach { a ->
            val on = a.pkg in filter.packages
            DropdownMenuItem(
              text = { Text("${a.label} (${a.count})") },
              leadingIcon = { Checkbox(checked = on, onCheckedChange = null) },
              onClick = { onChange(filter.copy(packages = if (on) filter.packages - a.pkg else filter.packages + a.pkg)) },
            )
          }
        }
      }
    }
    // 4. Updated – only shown when NVD/OSV/MSRC changed CVEs you haven't opened yet.
    if (updatedCount > 0 || filter.updatedOnly) {
      item { SelectableChip(filter.updatedOnly, "Updated ($updatedCount)", { onChange(filter.copy(updatedOnly = !filter.updatedOnly)) }) }
    }
  }
}

@Composable
private fun severityColorFor(s: String) = Vulft.colors.severity(s).fill

/** CVE card from the component sheet: outlined look, radius 12, padding 16, row gap 8. */
@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun CveCard(item: VulnItem, selected: Boolean, selectionMode: Boolean, onClick: () -> Unit, onLongClick: () -> Unit) {
  val c = item.cve
  val freshUpdate = c.updatedAt > 0 && !c.updateSeen
  Card(
    modifier = Modifier.fillMaxWidth().combinedClickable(onClick = onClick, onLongClick = onLongClick),
    shape = MaterialTheme.shapes.medium,
    border = if (freshUpdate) androidx.compose.foundation.BorderStroke(1.5.dp, Vulft.colors.updated.text) else outlinedCardBorder(),
    colors = CardDefaults.cardColors(
      containerColor = if (selected) MaterialTheme.colorScheme.secondaryContainer else MaterialTheme.colorScheme.surfaceContainerLow,
    ),
  ) {
    Row(Modifier.padding(16.dp)) {
      if (selectionMode) {
        Checkbox(checked = selected, onCheckedChange = { onClick() })
        Spacer(Modifier.width(4.dp))
      }
      Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
          Text(c.id, style = MonoType.large, maxLines = 1, modifier = Modifier.weight(1f))
          SeverityBadge(c.severity, c.cvssScore)
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
          Row(Modifier.weight(1f), verticalAlignment = Alignment.Bottom, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(item.row.appLabel, style = MaterialTheme.typography.titleSmall, maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f, fill = false))
            item.row.appVersion?.let {
              Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
          }
          if (c.exploited) { Spacer(Modifier.width(8.dp)); ExploitedBadge() }
        }
        if (freshUpdate) {
          Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            UpdatedBadge()
            Text(c.updateNote, style = MaterialTheme.typography.bodySmall, color = Vulft.colors.updated.text, maxLines = 2, overflow = TextOverflow.Ellipsis)
          }
        }
        Text(c.description, style = MaterialTheme.typography.bodyMedium, maxLines = 3, overflow = TextOverflow.Ellipsis)
        item.fix?.let { item.fixSummary() }?.let { fixText ->
          Text(fixText, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.primary, maxLines = 1, overflow = TextOverflow.Ellipsis)
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
          Text("${c.published.take(10)} · EPSS ${pct(c.epss)}", style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.weight(1f))
          VersionStatus(item.affected, filled = false)
        }
      }
    }
  }
}
