package com.vulft.app

import android.app.Application
import android.content.Context
import androidx.room.Room
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkInfo
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import androidx.work.workDataOf
import com.vulft.app.data.AppDatabase
import com.vulft.app.data.Mailer
import com.vulft.app.data.Reports
import com.vulft.app.data.SettingsStore
import com.vulft.app.data.VulnItem
import com.vulft.app.data.VulnRepository
import java.text.DateFormat
import java.util.Date
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch

class VulFTApp : Application() {
  lateinit var container: AppContainer
    private set

  override fun onCreate() {
    super.onCreate()
    container = AppContainer(this)
    SyncScheduler.schedule(this, container.settings.current.syncHours)
    // Pick up installed apps right away (automatic monitoring) and fetch CVEs for any not synced yet.
    container.appScope.launch {
      runCatching { container.repo.refreshInstalledApps() }
      if (runCatching { container.repo.needsSync() }.getOrDefault(false)) SyncScheduler.runNow(this@VulFTApp)
    }
  }
}

val Context.container: AppContainer get() = (applicationContext as VulFTApp).container

class AppContainer(private val context: Context) {
  val db: AppDatabase = Room.databaseBuilder(context, AppDatabase::class.java, "vulft.db").addMigrations(AppDatabase.MIGRATION_1_2, AppDatabase.MIGRATION_2_3, AppDatabase.MIGRATION_3_4, AppDatabase.MIGRATION_4_5).fallbackToDestructiveMigration(true).build()
  val settings = SettingsStore(context)
  val repo = VulnRepository(context, db, settings)
  val appScope = kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.SupervisorJob() + kotlinx.coroutines.Dispatchers.IO)

  /** Full sync + email for new CVEs that match the alert rules. */
  suspend fun syncAndAlert(progress: suspend (String) -> Unit) {
    try {
      progress("Scanning installed apps…")
      repo.refreshInstalledApps()
      val warnings = repo.sync(progress)
      val alertMsg = processAlerts(progress)
      // Phone notification for critical, actively exploited CVEs in tracked apps (each once).
      runCatching { CriticalNotifier.process(context, repo.currentItems(), settings.current) }
      val status = (if (warnings.isEmpty()) "OK" else "Partly OK · ${warnings.size} failed: ${warnings.joinToString("; ").take(300)}") +
        (alertMsg?.let { m -> " · $m" } ?: "")
      settings.update { it.copy(lastSync = System.currentTimeMillis(), lastSyncStatus = status) }
    } catch (e: Exception) {
      settings.update { it.copy(lastSyncStatus = "Failed: ${e.message ?: e.javaClass.simpleName}") }
      throw e
    }
  }

  private suspend fun processAlerts(progress: suspend (String) -> Unit): String? {
    val pending = repo.unalertedLinks()
    if (pending.isEmpty()) return null
    val s = settings.current
    val pendingKeys = pending.map { it.cpeKey to it.cveId }.toSet()
    val canSend = s.alerts.enabled && s.smtp.isConfigured
    // Match each source's row (that's what "alerted" is tracked on), then merge sources so each app+CVE is emailed once.
    val matching = if (canSend) repo.currentItemsRaw().filter { (it.row.cpeKey to it.cve.id) in pendingKeys && s.alerts.matches(it) } else emptyList()
    val toSend = com.vulft.app.data.VulnItem.dedupe(matching)
    var msg: String? = null
    if (toSend.isNotEmpty()) {
      progress("Sending alert email (${toSend.size} CVEs)…")
      try {
        Mailer.send(s.smtp, "[VulFT] ${toSend.size} new vulnerabilities in your apps", Reports.emailHtml("New vulnerabilities in your apps", toSend))
        msg = "emailed ${toSend.size} new CVEs"
      } catch (e: Exception) {
        // Keep matching links un-alerted so the next sync retries.
        val failed = matching.map { it.row.cpeKey to it.cve.id }.toSet()
        pending.filter { (it.cpeKey to it.cveId) !in failed }.forEach { repo.markAlerted(it.cpeKey, it.cveId) }
        return "email failed: ${e.message}"
      }
    }
    pending.forEach { repo.markAlerted(it.cpeKey, it.cveId) }
    return msg
  }

  /** Email an on-demand report of the given items. */
  suspend fun emailReport(title: String, items: List<VulnItem>) =
    Mailer.send(settings.current.smtp, "[VulFT] $title (${items.size})", Reports.emailHtml(title, items))
}

class SyncWorker(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {
  override suspend fun doWork(): Result = try {
    applicationContext.container.syncAndAlert { setProgress(workDataOf(KEY_PROGRESS to it)) }
    Result.success()
  } catch (e: Exception) {
    if (runAttemptCount < 2) Result.retry() else Result.failure(workDataOf(KEY_ERROR to (e.message ?: "error")))
  }

  companion object {
    const val KEY_PROGRESS = "progress"
    const val KEY_ERROR = "error"
  }
}

object SyncScheduler {
  private const val PERIODIC = "vulft-periodic-sync"
  private const val NOW = "vulft-sync-now"
  private val constraints = Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build()

  fun schedule(context: Context, hours: Int, replace: Boolean = false) {
    val req = PeriodicWorkRequestBuilder<SyncWorker>(hours.toLong().coerceAtLeast(1), TimeUnit.HOURS).setConstraints(constraints).build()
    WorkManager.getInstance(context).enqueueUniquePeriodicWork(PERIODIC, if (replace) ExistingPeriodicWorkPolicy.UPDATE else ExistingPeriodicWorkPolicy.KEEP, req)
  }

  fun runNow(context: Context) {
    val req = OneTimeWorkRequestBuilder<SyncWorker>().setConstraints(constraints).build()
    WorkManager.getInstance(context).enqueueUniqueWork(NOW, ExistingWorkPolicy.KEEP, req)
  }

  /** null when idle, otherwise the current progress message. */
  fun progress(context: Context): Flow<String?> =
    WorkManager.getInstance(context).getWorkInfosForUniqueWorkFlow(NOW).map { infos ->
      val running = infos.firstOrNull { it.state == WorkInfo.State.RUNNING || it.state == WorkInfo.State.ENQUEUED }
      running?.let { it.progress.getString(SyncWorker.KEY_PROGRESS) ?: if (it.state == WorkInfo.State.ENQUEUED) "Waiting for network…" else "Syncing…" }
    }
}

fun formatTime(ms: Long): String = if (ms <= 0) "never" else DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT).format(Date(ms))
