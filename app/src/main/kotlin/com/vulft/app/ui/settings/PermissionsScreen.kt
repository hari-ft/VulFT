package com.vulft.app.ui.settings

import android.content.Context
import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.PermissionInfo
import android.net.ConnectivityManager
import android.net.Uri
import android.os.Build
import android.os.PowerManager
import android.provider.Settings
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.LifecycleResumeEffect
import com.vulft.app.ui.common.BackTopBar
import androidx.compose.foundation.background
import androidx.compose.foundation.shape.RoundedCornerShape
import com.vulft.app.ui.common.SectionCard
import com.vulft.app.ui.theme.MonoType
import com.vulft.app.ui.theme.Vulft

/** One permission VulFT requests, as Android reports it right now. */
data class PermissionStatus(
  val name: String,
  val label: String,
  val type: String,
  val granted: Boolean,
  val purpose: String,
)

/** Why VulFT (or one of its libraries) asks for each permission. */
private val purposes = mapOf(
  "android.permission.INTERNET" to "Download CVE data from NVD, OSV.dev, Microsoft, CISA, FIRST and GitHub; send alert emails via your SMTP server.",
  "android.permission.ACCESS_NETWORK_STATE" to "Only sync when the phone is online.",
  "android.permission.QUERY_ALL_PACKAGES" to "List the apps installed on this phone and their versions, so their CVEs can be checked.",
  "android.permission.RECEIVE_BOOT_COMPLETED" to "Added by WorkManager: keeps the automatic sync schedule after the phone restarts.",
  "android.permission.WAKE_LOCK" to "Added by WorkManager: keeps the phone awake for the few seconds a background sync runs.",
  "android.permission.FOREGROUND_SERVICE" to "Added by WorkManager: lets a long sync finish if Android asks it to run in the foreground.",
  "android.permission.POST_NOTIFICATIONS" to "Notify you when an app or product you track has a critical, actively exploited vulnerability.",
)

private fun typeOf(pi: PermissionInfo?): String {
  if (pi == null) return "Custom"
  val base = if (Build.VERSION.SDK_INT >= 28) pi.protection else pi.protectionLevel and PermissionInfo.PROTECTION_MASK_BASE
  return when (base) {
    PermissionInfo.PROTECTION_NORMAL -> "Normal"
    PermissionInfo.PROTECTION_DANGEROUS -> "Runtime (asks you)"
    PermissionInfo.PROTECTION_SIGNATURE -> "Signature"
    else -> "Special"
  }
}

fun readPermissions(context: Context): List<PermissionStatus> {
  val pm = context.packageManager
  @Suppress("DEPRECATION")
  val info: PackageInfo = if (Build.VERSION.SDK_INT >= 33)
    pm.getPackageInfo(context.packageName, PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong()))
  else pm.getPackageInfo(context.packageName, PackageManager.GET_PERMISSIONS)
  val names = info.requestedPermissions.orEmpty()
  val flags = info.requestedPermissionsFlags ?: IntArray(names.size)
  return names.mapIndexed { i, name ->
    val pi = runCatching { pm.getPermissionInfo(name, 0) }.getOrNull()
    val isOwn = name.startsWith(context.packageName)
    PermissionStatus(
      name = name,
      label = pi?.loadLabel(pm)?.toString()?.replaceFirstChar { it.uppercase() }?.takeIf { it != name } ?: name.substringAfterLast('.'),
      type = typeOf(pi),
      granted = (flags.getOrElse(i) { 0 } and PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0,
      purpose = purposes[name] ?: if (isOwn) "Internal to VulFT: protects its own background receivers from other apps. Added by AndroidX."
        else "Added by a library VulFT uses.",
    )
  }.sortedWith(compareBy({ it.name !in purposes }, { it.label }))
}

@Composable
fun PermissionsScreen(onBack: () -> Unit) {
  val context = LocalContext.current
  // Re-read whenever the screen comes back (e.g. after changing something in system settings).
  var refresh by remember { mutableIntStateOf(0) }
  LifecycleResumeEffect(Unit) { refresh++; onPauseOrDispose { } }
  val perms = remember(refresh) { readPermissions(context) }
  val power = context.getSystemService(Context.POWER_SERVICE) as PowerManager
  val batteryUnrestricted = remember(refresh) { power.isIgnoringBatteryOptimizations(context.packageName) }
  val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
  val bgData = remember(refresh) { cm.restrictBackgroundStatus }
  val pauseOn = remember(refresh) { com.vulft.app.CriticalNotifier.pauseIfUnusedOn(context) }
  val notifyOk = remember(refresh) { com.vulft.app.CriticalNotifier.canNotify(context) }
  val askNotify = androidx.activity.compose.rememberLauncherForActivityResult(
    androidx.activity.result.contract.ActivityResultContracts.RequestPermission()) { refresh++ }
  val ok = Vulft.colors.updated
  val warn = Vulft.colors.affected

  Scaffold(topBar = { BackTopBar("App permissions", onBack) }) { padding ->
    Column(Modifier.padding(padding).fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
      Text("Everything VulFT is allowed to do on this phone, as Android reports it now. VulFT asks for no location, camera, microphone, contacts, storage or SMS access.",
        style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)

      SectionCard("Permissions (${perms.count { it.granted }} of ${perms.size} granted)") {
        perms.forEachIndexed { i, p ->
          Row(verticalAlignment = Alignment.Top) {
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
              Text(p.label, style = MaterialTheme.typography.titleSmall)
              Text(p.name, style = MonoType.small, color = MaterialTheme.colorScheme.onSurfaceVariant)
              Text(p.purpose, style = MaterialTheme.typography.bodySmall)
              Text("Type: ${p.type}", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            if (p.granted) Pill("Granted", ok.fill, ok.text) else Pill("Not granted", warn.fill, warn.text)
          }
          if (i < perms.lastIndex) HorizontalDivider(Modifier.padding(vertical = 4.dp), color = MaterialTheme.colorScheme.outlineVariant)
        }
      }

      SectionCard("Alerts and hibernation") {
        StatusRow("Notifications", if (notifyOk) "Allowed – you'll be alerted about critical exploited CVEs" else "Blocked – VulFT can't alert you", notifyOk)
        if (!notifyOk) {
          OutlinedButton(onClick = {
            val p = context.getSharedPreferences("vulft_ui", Context.MODE_PRIVATE)
            if (Build.VERSION.SDK_INT >= 33 && !p.getBoolean("notif_denied_once", false)) {
              p.edit().putBoolean("notif_denied_once", true).apply()
              askNotify.launch(android.Manifest.permission.POST_NOTIFICATIONS)
            } else {
              // After a refusal Android won't show the prompt again: open the app's notification settings instead.
              context.startActivity(Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).putExtra(Settings.EXTRA_APP_PACKAGE, context.packageName)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            }
          }) { Text("Allow notifications") }
        }
        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
        StatusRow("Pause app activity if unused", when (pauseOn) {
          true -> "On – if VulFT isn't opened for a few months, Android removes its permissions and stops syncs and alerts"
          false -> "Off – VulFT keeps syncing and alerting even if you don't open it"
          null -> "Not used on this Android version"
        }, pauseOn != true)
        if (pauseOn == true) {
          OutlinedButton(onClick = {
            context.startActivity(com.vulft.app.CriticalNotifier.pauseIfUnusedSettingsIntent(context).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
          }) { Text("Turn off in Android settings") }
        }
      }

      SectionCard("Background sync") {
        StatusRow("Battery optimisation", if (batteryUnrestricted) "Unrestricted – syncs run on time" else "Optimised – Android may delay automatic syncs", batteryUnrestricted)
        OutlinedButton(onClick = {
          context.startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        }) { Text("Battery settings") }
        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
        val bgOk = bgData != ConnectivityManager.RESTRICT_BACKGROUND_STATUS_ENABLED
        StatusRow("Background data", when (bgData) {
          ConnectivityManager.RESTRICT_BACKGROUND_STATUS_ENABLED -> "Blocked by Data Saver – syncs only on Wi-Fi or when the app is open"
          ConnectivityManager.RESTRICT_BACKGROUND_STATUS_WHITELISTED -> "Allowed (exempt from Data Saver)"
          else -> "Allowed"
        }, bgOk)
      }

      Button(onClick = {
        context.startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:${context.packageName}")).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
      }, modifier = Modifier.fillMaxWidth()) { Text("Open Android app settings for VulFT") }
      Text("Normal and special permissions are granted when the app is installed and can't be switched off individually; Android lets you uninstall or restrict background use instead.",
        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
  }
}

@Composable
private fun StatusRow(title: String, value: String, good: Boolean) {
  Row(verticalAlignment = Alignment.CenterVertically) {
    Column(Modifier.weight(1f)) {
      Text(title, style = MaterialTheme.typography.titleSmall)
      Text(value, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
    val c = if (good) Vulft.colors.updated else Vulft.colors.affected
    Pill(if (good) "OK" else "Check", c.fill, c.text)
  }
}

/** Small status pill (green = fine, amber = worth checking), matching the app's status badges. */
@Composable
private fun Pill(text: String, bg: Color, fg: Color) {
  Text(text, style = MaterialTheme.typography.labelMedium, color = fg,
    modifier = Modifier.background(bg, RoundedCornerShape(6.dp)).padding(horizontal = 8.dp, vertical = 3.dp))
}
