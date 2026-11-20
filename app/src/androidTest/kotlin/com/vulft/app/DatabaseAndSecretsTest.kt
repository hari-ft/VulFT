package com.vulft.app

import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.vulft.app.data.AppDatabase
import com.vulft.app.data.AppEntry
import com.vulft.app.data.CveEntry
import com.vulft.app.data.ProductCve
import com.vulft.app.data.SecretBox
import com.vulft.app.data.VulnItem
import com.vulft.app.data.linkPkg
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** On-device checks for the parts unit tests can't reach: Room queries and the Android Keystore. */
@RunWith(AndroidJUnit4::class)
class DatabaseAndSecretsTest {
  private lateinit var db: AppDatabase

  @Before fun setUp() {
    db = Room.inMemoryDatabaseBuilder(ApplicationProvider.getApplicationContext(), AppDatabase::class.java).build()
  }

  @After fun tearDown() = db.close()

  private fun cve(id: String) = CveEntry(id, "test", "2026-01-01", "2026-01-01", "", 9.8, "CRITICAL", "3.1", null, null, null, "", "[]")

  @Test fun linkRowsJoinAndMergeIntoOneCard() = runBlocking {
    val dao = db.dao()
    val app = AppEntry("com.microsoft.emmx", "Edge", "130.0", "Browser", isSystem = false, watched = true,
      cpeVendor = "microsoft", cpeProduct = "edge_chromium")
    val link = AppEntry(linkPkg(app.packageName, "msrc", "Microsoft Edge for Android"), "Edge", "130.0", "Browser", isSystem = false,
      watched = true, cpeVendor = "msrc", cpeProduct = "Microsoft Edge for Android")
    dao.upsertApps(listOf(app, link))
    dao.upsertCves(listOf(cve("CVE-2026-1")))
    dao.upsertLinks(listOf(
      ProductCve("microsoft:edge_chromium", "CVE-2026-1", "[]", 0),
      ProductCve("msrc:Microsoft Edge for Android", "CVE-2026-1", "[]", 0, fixJson = """{"source":"MSRC","fixedBuild":"129.0"}"""),
    ))
    val rows = dao.rows()
    assertEquals(2, rows.size) // one per source
    val items = VulnItem.dedupe(rows.map(VulnItem::from))
    assertEquals(1, items.size) // one card for the app
    assertEquals("com.microsoft.emmx", items[0].appPkg)
  }

  @Test fun unwatchedAppsAndUntrackedCvesAreNotListed() = runBlocking {
    val dao = db.dao()
    dao.upsertApps(listOf(AppEntry("a.b", "A", "1", "X", isSystem = false, watched = false, cpeVendor = "v", cpeProduct = "p")))
    dao.upsertCves(listOf(cve("CVE-2026-2"), cve("CVE-2026-3")))
    dao.upsertLinks(listOf(ProductCve("v:p", "CVE-2026-2", "[]", 0)))
    assertEquals(0, dao.rows().size)
    dao.deleteUntrackedCves()
    assertEquals(listOf("CVE-2026-2"), dao.allCveIds())
  }

  @Test fun secretsRoundTripThroughKeystore() {
    val secret = "app-password-123!"
    val stored = SecretBox.encrypt(secret)
    assertNotEquals(secret, stored)
    assertEquals(secret, SecretBox.decrypt(stored))
    assertEquals("", SecretBox.encrypt(""))
  }
}
