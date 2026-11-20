package com.vulft.app

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import androidx.core.content.edit
import androidx.core.net.toUri
import com.vulft.app.data.Affected
import com.vulft.app.data.AppSettings
import com.vulft.app.data.VulnItem

/**
 * Phone notifications for CVEs that are both severe and actively exploited (CISA KEV or Microsoft)
 * in apps/products the user tracks. Each app + CVE is notified once.
 */
object CriticalNotifier {
  const val CHANNEL = "critical-exploited"
  const val EXTRA_CVE = "com.vulft.app.CVE_ID"
  private const val PREFS = "vulft_notified"
  private const val KEY = "keys"
  private const val SUMMARY_ID = 1

  fun canNotify(context: Context): Boolean =
    (Build.VERSION.SDK_INT < 33 || ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED) &&
      NotificationManagerCompat.from(context).areNotificationsEnabled()

  fun ensureChannel(context: Context) {
    val nm = context.getSystemService(NotificationManager::class.java)
    if (nm.getNotificationChannel(CHANNEL) == null) {
      nm.createNotificationChannel(NotificationChannel(CHANNEL, "Critical exploited vulnerabilities", NotificationManager.IMPORTANCE_HIGH).apply {
        description = "Critical (or high) CVEs that are being actively exploited in apps and products you track"
      })
    }
  }

  /** Items that should alert: tracked, actively exploited, severe enough, and not ruled out by your version. */
  fun qualifying(items: List<VulnItem>, s: AppSettings): List<VulnItem> {
    val severities = if (s.notifyIncludeHigh) setOf("CRITICAL", "HIGH") else setOf("CRITICAL")
    return items.filter { it.cve.exploited && it.cve.severity in severities && it.affected != Affected.NO }
  }

  /** Posts notifications for qualifying items not notified before. Returns how many were new. */
  fun process(context: Context, items: List<VulnItem>, s: AppSettings): Int {
    if (!s.notifyCriticalExploited) return 0
    val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    // Ordered oldest → newest, so trimming drops the oldest (a plain Set would drop random entries).
    val seenList = readSeen(prefs)
    val seen = seenList.toHashSet()
    val fresh = qualifying(items, s).filter { it.key !in seen }.sortedByDescending { it.cve.cvssScore ?: 0.0 }
    if (fresh.isEmpty()) return 0
    if (!canNotify(context)) return 0 // try again after the user allows notifications
    ensureChannel(context)
    val nm = NotificationManagerCompat.from(context)
    try {
      if (fresh.size == 1) {
        val i = fresh[0]
        nm.notify(i.key.hashCode(), build(context, i.cve.id,
          "Exploited ${i.cve.severity.lowercase()} CVE in ${i.row.appLabel}",
          "${i.cve.id}: ${i.cve.description.take(140)}").build())
      } else {
        val style = NotificationCompat.InboxStyle().setSummaryText("Tap to review")
        fresh.take(6).forEach { style.addLine("${it.cve.id} · ${it.row.appLabel}") }
        if (fresh.size > 6) style.addLine("+${fresh.size - 6} more")
        nm.notify(SUMMARY_ID, build(context, null,
          "${fresh.size} actively exploited vulnerabilities in your apps",
          fresh.take(3).joinToString(", ") { "${it.cve.id} (${it.row.appLabel})" }).setStyle(style).build())
      }
    } catch (_: SecurityException) {
      return 0
    }
    val updated = (seenList + fresh.map { it.key }).takeLast(3000)
    prefs.edit { putString(KEY_LIST, updated.joinToString("\n")).remove(KEY) }
    return fresh.size
  }

  private const val KEY_LIST = "keys_ordered"

  /** Notified app+CVE keys, oldest first (migrates the earlier unordered set). */
  private fun readSeen(prefs: android.content.SharedPreferences): List<String> =
    prefs.getString(KEY_LIST, null)?.split('\n')?.filter { it.isNotBlank() }
      ?: prefs.getStringSet(KEY, emptySet()).orEmpty().toList()

  private fun build(context: Context, cveId: String?, title: String, text: String): NotificationCompat.Builder {
    val open = Intent(context, MainActivity::class.java).apply {
      flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP
      cveId?.let { putExtra(EXTRA_CVE, it) }
    }
    val pi = PendingIntent.getActivity(context, (cveId ?: "list").hashCode(), open, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
    return NotificationCompat.Builder(context, CHANNEL)
      .setSmallIcon(R.drawable.ic_stat_vulft)
      .setContentTitle(title)
      .setContentText(text)
      .setStyle(NotificationCompat.BigTextStyle().bigText(text))
      .setPriority(NotificationCompat.PRIORITY_HIGH)
      .setCategory(NotificationCompat.CATEGORY_ALARM)
      .setContentIntent(pi)
      .setAutoCancel(true)
  }

  /** Android "Pause app activity if unused": true = VulFT may be hibernated (syncs and notifications stop). */
  fun pauseIfUnusedOn(context: Context): Boolean? =
    if (Build.VERSION.SDK_INT >= 30) !context.packageManager.isAutoRevokeWhitelisted else null

  fun pauseIfUnusedSettingsIntent(context: Context): Intent =
    if (Build.VERSION.SDK_INT >= 30) Intent(Intent.ACTION_AUTO_REVOKE_PERMISSIONS, "package:${context.packageName}".toUri())
    else Intent(android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS, "package:${context.packageName}".toUri())
}
