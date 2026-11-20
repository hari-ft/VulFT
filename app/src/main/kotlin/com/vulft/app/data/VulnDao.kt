package com.vulft.app.data

import androidx.room.Dao
import androidx.room.Database
import androidx.room.Query
import androidx.room.RoomDatabase
import androidx.room.Upsert
import kotlinx.coroutines.flow.Flow

const val ROW_SQL =
  "SELECT c.*, a.packageName AS pkg, a.label AS appLabel, a.versionName AS appVersion, a.category AS appCategory, " +
    "p.cpeKey AS cpeKey, p.rangesJson AS ranges, p.firstSeen AS firstSeen, p.alerted AS alerted, p.fixJson AS fixJson " +
    "FROM product_cves p JOIN cves c ON c.id = p.cveId " +
    "JOIN apps a ON a.watched = 1 AND (a.cpeVendor || ':' || a.cpeProduct) = p.cpeKey"

@Dao
interface VulnDao {
  // ---- apps
  @Query("SELECT * FROM apps ORDER BY label COLLATE NOCASE") fun appsFlow(): Flow<List<AppEntry>>
  @Query("SELECT * FROM apps") suspend fun allApps(): List<AppEntry>
  @Query("SELECT * FROM apps WHERE watched = 1") suspend fun watchedApps(): List<AppEntry>
  @Query("SELECT * FROM apps WHERE packageName = :pkg") suspend fun app(pkg: String): AppEntry?
  @Upsert suspend fun upsertApps(apps: List<AppEntry>)
  /** A user tick/untick: also recorded as watchChoice so automatic monitoring won't override it. */
  @Query("UPDATE apps SET watched = :watched, watchChoice = :watched WHERE packageName = :pkg") suspend fun setWatched(pkg: String, watched: Boolean)
  @Query("UPDATE apps SET watched = :watched, watchChoice = :watched WHERE packageName IN (:pkgs)") suspend fun setWatched(pkgs: List<String>, watched: Boolean)
  @Query("UPDATE apps SET watchChoice = NULL WHERE packageName NOT LIKE 'manual:%' AND packageName NOT LIKE 'link:%'") suspend fun clearWatchChoices()
  /** Extra source links follow their app's watched state. */
  @Query("UPDATE apps SET watched = :watched WHERE packageName LIKE 'link:' || :parent || '|%'") suspend fun setLinksWatched(parent: String, watched: Boolean)
  @Query("UPDATE apps SET cpeVendor = :vendor, cpeProduct = :product, mappingSource = :source, lastSynced = 0 WHERE packageName = :pkg")
  suspend fun setMapping(pkg: String, vendor: String?, product: String?, source: String?)
  @Query("UPDATE apps SET lastSynced = :time WHERE cpeVendor = :vendor AND cpeProduct = :product")
  suspend fun setSynced(vendor: String, product: String, time: Long)
  @Query("DELETE FROM apps WHERE packageName = :pkg") suspend fun deleteApp(pkg: String)
  @Query("UPDATE apps SET versionName = :version WHERE packageName = :pkg") suspend fun setVersion(pkg: String, version: String?)
  @Query("UPDATE apps SET lastSynced = 0 WHERE packageName = :pkg") suspend fun resetSynced(pkg: String)

  // ---- cves
  @Query("SELECT * FROM cves WHERE id = :id") suspend fun cve(id: String): CveEntry?
  @Query("SELECT * FROM cves WHERE id IN (:ids)") suspend fun cves(ids: List<String>): List<CveEntry>
  @Query("SELECT * FROM cves WHERE id = :id") fun cveFlow(id: String): Flow<CveEntry?>
  @Upsert suspend fun upsertCves(cves: List<CveEntry>)
  @Query("UPDATE cves SET updateSeen = 1 WHERE id = :id") suspend fun markUpdateSeen(id: String)
  @Query("UPDATE cves SET kev = 0, kevDateAdded = NULL, kevDueDate = NULL, kevAction = NULL, kevRansomware = NULL, kevName = NULL")
  suspend fun clearKev()
  @Query("UPDATE cves SET kev = 1, kevDateAdded = :added, kevDueDate = :due, kevAction = :action, kevRansomware = :ransomware, kevName = :name WHERE id = :id")
  suspend fun setKev(id: String, added: String?, due: String?, action: String?, ransomware: String?, name: String?)
  @Query("UPDATE cves SET epss = :epss, epssPercentile = :percentile WHERE id = :id")
  suspend fun setEpss(id: String, epss: Double, percentile: Double)
  @Query("SELECT id FROM cves") suspend fun allCveIds(): List<String>
  @Query("SELECT id FROM cves WHERE epss IS NULL") suspend fun idsWithoutEpss(): List<String>

  // ---- links
  @Upsert suspend fun upsertLinks(links: List<ProductCve>)
  @Query("SELECT * FROM product_cves WHERE cpeKey = :cpeKey") suspend fun linksFor(cpeKey: String): List<ProductCve>
  @Query("SELECT * FROM product_cves WHERE alerted = 0") suspend fun unalertedLinks(): List<ProductCve>
  @Query("UPDATE product_cves SET alerted = 1 WHERE cpeKey = :cpeKey AND cveId = :cveId") suspend fun markAlerted(cpeKey: String, cveId: String)
  @Query("SELECT cpeKey, COUNT(*) AS n FROM product_cves GROUP BY cpeKey") fun countsFlow(): Flow<List<CpeCount>>

  // ---- list rows
  @Query(ROW_SQL) fun rowsFlow(): Flow<List<CveRow>>
  @Query(ROW_SQL) suspend fun rows(): List<CveRow>
  @Query("$ROW_SQL WHERE c.id = :id") fun rowsForCve(id: String): Flow<List<CveRow>>
}

@Database(entities = [AppEntry::class, CveEntry::class, ProductCve::class], version = 5, exportSchema = false)
abstract class AppDatabase : RoomDatabase() {
  abstract fun dao(): VulnDao

  companion object {
    val MIGRATION_1_2 = object : androidx.room.migration.Migration(1, 2) {
      override fun migrate(db: androidx.sqlite.db.SupportSQLiteDatabase) {
        db.execSQL("ALTER TABLE cves ADD COLUMN affectedProducts TEXT NOT NULL DEFAULT ''")
      }
    }
    val MIGRATION_2_3 = object : androidx.room.migration.Migration(2, 3) {
      override fun migrate(db: androidx.sqlite.db.SupportSQLiteDatabase) {
        db.execSQL("ALTER TABLE apps ADD COLUMN watchChoice INTEGER")
        // Apps the user already ticked keep that as an explicit choice.
        db.execSQL("UPDATE apps SET watchChoice = 1 WHERE watched = 1")
      }
    }
    val MIGRATION_3_4 = object : androidx.room.migration.Migration(3, 4) {
      override fun migrate(db: androidx.sqlite.db.SupportSQLiteDatabase) {
        db.execSQL("ALTER TABLE cves ADD COLUMN updatedAt INTEGER NOT NULL DEFAULT 0")
        db.execSQL("ALTER TABLE cves ADD COLUMN updateNote TEXT NOT NULL DEFAULT ''")
        db.execSQL("ALTER TABLE cves ADD COLUMN updateSeen INTEGER NOT NULL DEFAULT 1")
      }
    }
    val MIGRATION_4_5 = object : androidx.room.migration.Migration(4, 5) {
      override fun migrate(db: androidx.sqlite.db.SupportSQLiteDatabase) {
        db.execSQL("ALTER TABLE cves ADD COLUMN sources TEXT NOT NULL DEFAULT ''")
        db.execSQL("ALTER TABLE cves ADD COLUMN msExploited INTEGER NOT NULL DEFAULT 0")
        db.execSQL("ALTER TABLE product_cves ADD COLUMN fixJson TEXT NOT NULL DEFAULT ''")
        db.execSQL("UPDATE cves SET sources = 'NVD'")
      }
    }
  }
}
