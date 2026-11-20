package com.vulft.app.ui.apps

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.ArrowDropDown
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.vulft.app.data.AppEntry
import com.vulft.app.data.cpeKey
import com.vulft.app.data.productKeyLabel
import com.vulft.app.data.remote.MsrcProduct
import com.vulft.app.data.remote.OsvClient
import com.vulft.app.data.source
import com.vulft.app.ui.theme.MonoType
import kotlinx.coroutines.launch

/** Link an installed app to any of the product sources: NVD, Microsoft (MSRC) and OSV.dev. Several at once is fine. */
@Composable
fun LinkSourcesDialog(u: AppUi, vm: AppPickerViewModel, onDismiss: () -> Unit) {
  val app = u.app
  var tab by remember { mutableStateOf(0) }

  AlertDialog(
    onDismissRequest = onDismiss,
    title = { Text("Sources for ${app.label}") },
    text = {
      Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text("Linked", style = MaterialTheme.typography.titleSmall)
        if (!u.isLinked) {
          Text("Not linked yet. Most Play Store apps have no published CVEs; link one if its maker publishes them.",
            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        if (app.cpeKey() != null) LinkedRow(app) { vm.clearMainLink(app.packageName) }
        u.links.forEach { l -> LinkedRow(l) { vm.removeLink(l.packageName) } }
        HorizontalDivider()
        Text("Add a source", style = MaterialTheme.typography.titleSmall)
        SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
          listOf("NVD", "Microsoft", "OSV").forEachIndexed { i, label ->
            SegmentedButton(selected = tab == i, onClick = { tab = i }, shape = SegmentedButtonDefaults.itemShape(i, 3)) { Text(label) }
          }
        }
        when (tab) {
          0 -> CpeSearch(app.label, vm::search) { s -> vm.addLink(app.packageName, s.vendor, s.product) }
          1 -> MicrosoftSearch(app.label, vm) { p -> vm.addLink(app.packageName, "msrc", p.name) }
          else -> OsvAdd { eco, name -> vm.addLink(app.packageName, "osv:$eco", name) }
        }
      }
    },
    confirmButton = { TextButton(onClick = onDismiss) { Text("Done") } },
  )
}

@Composable
private fun LinkedRow(entry: AppEntry, onRemove: () -> Unit) {
  Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
    Column(Modifier.weight(1f)) {
      Text(entry.source().label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
      Text(productKeyLabel(entry.cpeVendor, entry.cpeProduct), style = MonoType.small)
    }
    IconButton(onClick = onRemove) { Icon(Icons.Outlined.Close, "Remove link") }
  }
}

@Composable
private fun MicrosoftSearch(initial: String, vm: AppPickerViewModel, onPick: (MsrcProduct) -> Unit) {
  val scope = rememberCoroutineScope()
  var q by remember { mutableStateOf(initial.removePrefix("Microsoft ").ifBlank { initial }) }
  var results by remember { mutableStateOf<List<MsrcProduct>?>(null) }
  var busy by remember { mutableStateOf(false) }
  var error by remember { mutableStateOf<String?>(null) }
  Row(verticalAlignment = Alignment.CenterVertically) {
    OutlinedTextField(q, { q = it }, label = { Text("Microsoft product") }, singleLine = true, modifier = Modifier.weight(1f))
    TextButton(enabled = q.isNotBlank() && !busy, onClick = {
      scope.launch {
        busy = true; error = null
        runCatching { vm.searchMicrosoft(q) }.onSuccess { results = it }.onFailure { error = it.message }
        busy = false
      }
    }) { Text("Search") }
  }
  Text("Names are case-sensitive, e.g. \"Edge\", \"Teams\", \"Office\".", style = MaterialTheme.typography.bodySmall,
    color = MaterialTheme.colorScheme.onSurfaceVariant)
  when {
    busy -> CircularProgressIndicator(Modifier.padding(8.dp))
    error != null -> Text("Search failed: $error", color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
    results?.isEmpty() == true -> Text("No Microsoft products found.", style = MaterialTheme.typography.bodySmall)
  }
  results?.takeIf { it.isNotEmpty() }?.let { list ->
    Column(Modifier.heightIn(max = 220.dp).verticalScroll(rememberScrollState())) {
      list.forEach { p ->
        Column(Modifier.fillMaxWidth().clickable { onPick(p) }.padding(vertical = 6.dp)) {
          Text(p.name, style = MaterialTheme.typography.bodyMedium)
          Text(p.family, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
      }
    }
  }
}

@Composable
private fun OsvAdd(onAdd: (String, String) -> Unit) {
  var eco by remember { mutableStateOf("PyPI") }
  var name by remember { mutableStateOf("") }
  var menu by remember { mutableStateOf(false) }
  Text("For open-source software: the app's package in an ecosystem OSV.dev covers.", style = MaterialTheme.typography.bodySmall,
    color = MaterialTheme.colorScheme.onSurfaceVariant)
  Box {
    OutlinedButton(onClick = { menu = true }, modifier = Modifier.fillMaxWidth()) {
      Text("Ecosystem: $eco", modifier = Modifier.weight(1f)); Icon(Icons.Outlined.ArrowDropDown, null)
    }
    DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
      OsvClient.ecosystems.forEach { e -> DropdownMenuItem(text = { Text(e) }, onClick = { eco = e; menu = false }) }
    }
  }
  OutlinedTextField(name, { name = it }, label = { Text("Package name (exact)") }, singleLine = true, modifier = Modifier.fillMaxWidth())
  Button(onClick = { onAdd(eco, name.trim()); name = "" }, enabled = name.isNotBlank()) { Text("Link package") }
}
