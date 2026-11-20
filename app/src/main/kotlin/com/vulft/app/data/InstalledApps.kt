package com.vulft.app.data

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build

data class ScannedApp(val packageName: String, val label: String, val versionName: String?, val category: String, val isSystem: Boolean)

object InstalledApps {
  fun scan(context: Context): List<ScannedApp> {
    val pm = context.packageManager
    @Suppress("DEPRECATION")
    val packages = if (Build.VERSION.SDK_INT >= 33) pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(0)) else pm.getInstalledPackages(0)
    return packages.mapNotNull { pi ->
      val ai = pi.applicationInfo ?: return@mapNotNull null
      if (pi.packageName == context.packageName) return@mapNotNull null
      ScannedApp(
        packageName = pi.packageName,
        label = ai.loadLabel(pm).toString(),
        versionName = pi.versionName,
        category = categoryName(context, ai),
        // Preinstalled apps you can open (Chrome, Gmail…) count as user apps; only background system components count as system.
        isSystem = (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0 && pm.getLaunchIntentForPackage(pi.packageName) == null,
      )
    }
  }

  private fun categoryName(context: Context, ai: ApplicationInfo): String =
    ApplicationInfo.getCategoryTitle(context, ai.category)?.toString() ?: "Other"
}
