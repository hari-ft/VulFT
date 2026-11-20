package com.vulft.app.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class VersionsTest {
  private val any = "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*"

  @Test fun compare() {
    assertTrue(Versions.compare("120.0.6099.144", "120.0.6099.71") > 0)
    assertTrue(Versions.compare("2.24.10.75", "2.24.9") > 0)
    assertEquals(0, Versions.compare("1.0", "1.0.0"))
    assertTrue(Versions.compare("1.0.1", "1.0.beta") > 0)
  }

  @Test fun ranges() {
    val r = listOf(CpeRange(any, endExcluding = "120.0.6099.199"))
    assertEquals(Affected.YES, Versions.evaluate("120.0.6099.144", r))
    assertEquals(Affected.NO, Versions.evaluate("121.0.1", r))
    assertEquals(Affected.UNKNOWN, Versions.evaluate(null, r))
    assertEquals(Affected.YES, Versions.evaluate("5", listOf(CpeRange(any))))
    assertEquals(Affected.YES, Versions.evaluate("2.21.1", listOf(CpeRange("cpe:2.3:a:whatsapp:whatsapp:2.21.1:*:*:*:*:android:*:*"))))
    assertEquals(Affected.NO, Versions.evaluate("2.21.2", listOf(CpeRange("cpe:2.3:a:whatsapp:whatsapp:2.21.1:*:*:*:*:android:*:*"))))
    assertEquals(Affected.YES, Versions.evaluate("3.5", listOf(CpeRange(any, startIncluding = "3.0", endIncluding = "3.5"))))
    // "-" = NVD has no version info (e.g. CVE-2013-6647) → unknown, not affected.
    assertEquals(Affected.UNKNOWN, Versions.evaluate("157.0.8103.78", listOf(CpeRange("cpe:2.3:a:google:chrome:-:*:*:*:*:*:*:*"))))
    // ...but a real range for the same CVE still decides it.
    val dash = CpeRange("cpe:2.3:a:google:chrome:-:*:*:*:*:*:*:*")
    assertEquals(Affected.NO, Versions.evaluate("157.0", listOf(dash, CpeRange(any, endExcluding = "32.0"))))
    assertEquals(Affected.YES, Versions.evaluate("31.0", listOf(dash, CpeRange(any, endExcluding = "32.0"))))
  }
}
