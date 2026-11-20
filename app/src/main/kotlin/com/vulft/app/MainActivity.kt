package com.vulft.app

import androidx.core.content.edit
import android.Manifest
import android.content.Intent
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.Modifier
import com.vulft.app.ui.theme.VulFTTheme
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {
  /** CVE to open, from a tapped notification. */
  private val openCve = mutableStateOf<String?>(null)

  private val askNotifications = registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
    // A sync may already have found something to alert about – check now that we're allowed.
    if (granted) container.appScope.launch {
      runCatching { CriticalNotifier.process(applicationContext, container.repo.currentItems(), container.settings.current) }
    }
  }

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    openCve.value = intent?.getStringExtra(CriticalNotifier.EXTRA_CVE)
    maybeAskForNotifications()

    enableEdgeToEdge()
    setContent {
      VulFTTheme {
        Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
          MainNavigation(openCve = openCve.value, onCveOpened = { openCve.value = null })
        }
      }
    }
  }

  override fun onNewIntent(intent: Intent) {
    super.onNewIntent(intent)
    intent.getStringExtra(CriticalNotifier.EXTRA_CVE)?.let { openCve.value = it }
  }

  /** Android 13+: ask once for notification permission (needed for critical-exploited alerts). */
  private fun maybeAskForNotifications() {
    if (Build.VERSION.SDK_INT < 33 || !container.settings.current.notifyCriticalExploited) return
    if (CriticalNotifier.canNotify(this)) return
    val prefs = getSharedPreferences("vulft_ui", MODE_PRIVATE)
    if (prefs.getBoolean("asked_notifications", false)) return
    prefs.edit { putBoolean("asked_notifications", true) }
    askNotifications.launch(Manifest.permission.POST_NOTIFICATIONS)
  }
}
