package com.vulft.app.ui.common

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.outlined.HelpOutline
import androidx.compose.material.icons.outlined.Description
import androidx.compose.material.icons.outlined.LocalFireDepartment
import androidx.compose.material.icons.outlined.Update
import androidx.compose.material.icons.outlined.Android
import androidx.compose.material.icons.outlined.VerifiedUser
import androidx.compose.material.icons.outlined.WarningAmber
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.runtime.getValue
import androidx.compose.runtime.produceState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.core.graphics.drawable.toBitmap
import com.vulft.app.data.Affected
import com.vulft.app.data.Severity
import com.vulft.app.ui.theme.Vulft

// ---------------------------------------------------------------- severity badge: label + score + bars, never colour alone

@Composable
fun SeverityBars(severity: String, color: Color, modifier: Modifier = Modifier) {
  val filled = when (severity) { "CRITICAL" -> 4; "HIGH" -> 3; "MEDIUM" -> 2; "LOW" -> 1; else -> 0 }
  Canvas(modifier.size(width = 18.dp, height = 10.dp)) {
    val w = 3.dp.toPx(); val gap = 2.dp.toPx()
    listOf(4, 6, 8, 10).forEachIndexed { i, h ->
      val hp = h.dp.toPx()
      drawRoundRect(
        color = if (i < filled) color else color.copy(alpha = 0.35f),
        topLeft = Offset(i * (w + gap), size.height - hp),
        size = Size(w, hp),
        cornerRadius = CornerRadius(0.5.dp.toPx()),
      )
    }
  }
}

@Composable
fun SeverityBadge(severity: String, score: Double?, modifier: Modifier = Modifier, large: Boolean = false) {
  val c = Vulft.colors.severity(severity)
  Row(
    modifier
      .height(if (large) 32.dp else 24.dp)
      .background(c.fill, RoundedCornerShape(if (large) 8.dp else 6.dp))
      .padding(horizontal = if (large) 12.dp else 8.dp),
    verticalAlignment = Alignment.CenterVertically,
    horizontalArrangement = Arrangement.spacedBy(6.dp),
  ) {
    SeverityBars(severity, c.text)
    Text(
      Severity.label(severity) + (score?.let { " $it" } ?: ""),
      color = c.text,
      style = if (large) MaterialTheme.typography.labelLarge else MaterialTheme.typography.labelMedium,
    )
  }
}

// ---------------------------------------------------------------- status badges

@Composable
private fun StatusBadge(text: String, icon: ImageVector, fg: Color, bg: Color?, border: Color? = null, dashed: Boolean = false, caps: Boolean = false) {
  val shape = RoundedCornerShape(6.dp)
  var m = Modifier.height(24.dp)
  if (bg != null) m = m.background(bg, shape)
  if (border != null && !dashed) m = m.border(1.dp, border, shape)
  if (border != null && dashed) {
    m = m.drawBehind {
      drawRoundRect(border, cornerRadius = CornerRadius(6.dp.toPx()),
        style = Stroke(1.dp.toPx(), pathEffect = PathEffect.dashPathEffect(floatArrayOf(4.dp.toPx(), 3.dp.toPx()))))
    }
  }
  Row(m.padding(start = 6.dp, end = 8.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(4.dp)) {
    Icon(icon, null, tint = fg, modifier = Modifier.size(16.dp))
    Text(if (caps) text.uppercase() else text, color = fg, style = if (caps) MaterialTheme.typography.labelSmall else MaterialTheme.typography.labelMedium)
  }
}

/** Actively exploited (CISA KEV). The one badge with no hue, so it can't be mistaken for a severity. */
@Composable
fun ExploitedBadge(text: String = "Exploited") =
  StatusBadge(text, Icons.Outlined.LocalFireDepartment, MaterialTheme.colorScheme.inverseOnSurface, MaterialTheme.colorScheme.inverseSurface, caps = true)

@Composable
fun RansomwareBadge() {
  val c = Vulft.colors.ransomware
  StatusBadge("Ransomware", Icons.Outlined.Description, c.text, c.fill, border = c.text, caps = true)
}

/** Green mark for a CVE that NVD changed since the last sync (shown until the user opens it). */
@Composable
fun UpdatedBadge(text: String = "Updated") {
  val c = Vulft.colors.updated
  StatusBadge(text, Icons.Outlined.Update, c.text, c.fill, caps = true)
}

/** Green banner on the detail screen: when it was updated and what changed. */
@Composable
fun UpdatedBanner(updatedAt: Long, note: String) {
  val c = Vulft.colors.updated
  Row(Modifier.fillMaxWidth().background(c.fill, RoundedCornerShape(12.dp)).padding(12.dp), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
    Icon(Icons.Outlined.Update, null, tint = c.text)
    Column {
      Text("Updated ${com.vulft.app.formatTime(updatedAt)}", style = MaterialTheme.typography.titleSmall, color = c.text)
      Text(note, style = MaterialTheme.typography.bodyMedium, color = c.text)
    }
  }
}

/** Version status. [filled] = badge look; otherwise text + icon only (card footers). */
@Composable
fun VersionStatus(affected: Affected, filled: Boolean = true) {
  val v = Vulft.colors
  when (affected) {
    Affected.YES -> StatusBadge("Your version affected", Icons.Outlined.WarningAmber, v.affected.text, if (filled) v.affected.fill else null)
    Affected.NO -> StatusBadge("Not your version", Icons.Outlined.VerifiedUser, v.notAffected.text, if (filled) v.notAffected.fill else null)
    Affected.UNKNOWN -> StatusBadge("Version unknown", Icons.AutoMirrored.Outlined.HelpOutline, MaterialTheme.colorScheme.onSurfaceVariant, null,
      border = if (filled) MaterialTheme.colorScheme.outline else null, dashed = true)
  }
}

// ---------------------------------------------------------------- cards, rows, bars

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun BackTopBar(title: String, onBack: () -> Unit, actions: @Composable () -> Unit = {}) {
  TopAppBar(
    title = { Text(title, maxLines = 1) },
    navigationIcon = { IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back") } },
    actions = { actions() },
  )
}

/** Level-1 card: surfaceContainerLow + 1 dp outlineVariant, no shadow, radius 12. */
@Composable
fun outlinedCardColors() = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow)

@Composable
fun outlinedCardBorder() = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant)

@Composable
fun SectionCard(title: String, modifier: Modifier = Modifier, content: @Composable () -> Unit) {
  Card(modifier.fillMaxWidth(), shape = MaterialTheme.shapes.medium, colors = outlinedCardColors(), border = outlinedCardBorder()) {
    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
      Text(title, style = MaterialTheme.typography.titleMedium)
      content()
    }
  }
}

/** Label left, value right, divider below (section card rows). */
@Composable
fun InfoRow(label: String, value: String, divider: Boolean = true, valueColor: Color = Color.Unspecified, onClick: (() -> Unit)? = null) {
  Column {
    Row(Modifier.fillMaxWidth().padding(vertical = 6.dp), verticalAlignment = Alignment.Top) {
      Text(label, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.width(120.dp))
      val text: @Composable () -> Unit = {
        Text(value, style = MaterialTheme.typography.bodyMedium.copy(fontFeatureSettings = "tnum"), textAlign = TextAlign.End,
          color = if (onClick != null) MaterialTheme.colorScheme.primary else valueColor, modifier = Modifier.weight(1f))
      }
      if (onClick != null) Box(Modifier.weight(1f), contentAlignment = Alignment.CenterEnd) { TextButton(onClick = onClick) { Text(value) } } else text()
    }
    if (divider) HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
  }
}

@Composable
fun EmptyState(icon: ImageVector, title: String, body: String, action: String? = null, onAction: () -> Unit = {}, secondary: String? = null, onSecondary: () -> Unit = {}) {
  Column(Modifier.fillMaxSize().padding(horizontal = 32.dp, vertical = 48.dp), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.Center) {
    Icon(icon, null, tint = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.size(48.dp))
    Spacer(Modifier.height(16.dp))
    Text(title, style = MaterialTheme.typography.titleMedium, textAlign = TextAlign.Center)
    Spacer(Modifier.height(8.dp))
    Text(body, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, textAlign = TextAlign.Center)
    if (action != null) { Spacer(Modifier.height(24.dp)); Button(onClick = onAction) { Text(action) } }
    if (secondary != null) TextButton(onClick = onSecondary) { Text(secondary) }
  }
}

/** Installed app icon (40 dp, radius 10) or a letter tile for added products. */
@Composable
fun AppIcon(packageName: String, label: String, size: Dp = 40.dp) {
  val context = LocalContext.current
  if (packageName == com.vulft.app.data.DEVICE_OS_PKG) {
    Box(Modifier.size(size).background(MaterialTheme.colorScheme.primaryContainer, RoundedCornerShape(10.dp)), contentAlignment = Alignment.Center) {
      Icon(Icons.Outlined.Android, null, tint = MaterialTheme.colorScheme.onPrimaryContainer)
    }
    return
  }
  // Load icons off the main thread (the picker shows ~400) and keep them in a small memory cache.
  val bitmap by produceState(initialValue = iconCache.get(packageName), packageName) {
    if (value == null) {
      value = withContext(Dispatchers.IO) {
        runCatching { context.packageManager.getApplicationIcon(packageName).toBitmap(96, 96).asImageBitmap() }.getOrNull()
      }?.also { iconCache.put(packageName, it) }
    }
  }
  val shape = RoundedCornerShape(10.dp)
  val bmp = bitmap
  if (bmp != null) {
    Image(bmp, null, Modifier.size(size).clip(shape))
  } else {
    Box(Modifier.size(size).background(MaterialTheme.colorScheme.surfaceContainerHighest, shape), contentAlignment = Alignment.Center) {
      Text(label.firstOrNull()?.uppercase() ?: "?", style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
  }
}

private val iconCache = android.util.LruCache<String, androidx.compose.ui.graphics.ImageBitmap>(200)

/** Always "94.2%" regardless of the phone's language (some locales would print "94,2%"). */
fun pct(d: Double?): String = d?.let { String.format(java.util.Locale.US, "%.1f%%", it * 100) } ?: "–"
