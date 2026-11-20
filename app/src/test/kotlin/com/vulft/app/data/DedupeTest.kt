package com.vulft.app.data

import org.junit.Assert.assertEquals
import org.junit.Test

class DedupeTest {
  private fun cve(id: String) = CveEntry(id, "d", "2026-01-01", "2026-01-01", "", 9.8, "CRITICAL", "3.1", null, null, null, "", "[]")

  private fun row(pkg: String, cpeKey: String, ranges: String = "[]", fix: String = "", version: String? = "130.0") =
    CveRow(cve("CVE-2026-1"), pkg, "Edge", version, "Browser", cpeKey, ranges, 0, true, fix)

  @Test fun sameAppSameCveFromTwoSourcesBecomesOne() {
    val nvd = VulnItem.from(row("com.microsoft.emmx", "microsoft:edge_chromium",
      ranges = """[{"criteria":"cpe:2.3:a:microsoft:edge_chromium:*:*:*:*:*:*:*:*","endExcluding":"131.0"}]"""))
    val msrc = VulnItem.from(row(linkPkg("com.microsoft.emmx", "msrc", "Microsoft Edge for Android"), "msrc:Microsoft Edge for Android",
      fix = """{"source":"MSRC","fixedBuild":"129.0"}"""))
    assertEquals(Affected.YES, nvd.affected)   // NVD range says < 131 is affected
    assertEquals(Affected.NO, msrc.affected)   // Microsoft says build 129 fixed it
    val merged = VulnItem.dedupe(listOf(nvd, msrc))
    assertEquals(1, merged.size)
    assertEquals(Affected.NO, merged[0].affected) // the source with fix data wins
    assertEquals("com.microsoft.emmx", merged[0].appPkg)
  }

  @Test fun unknownFixFallsBackToDecidedNvdAnswer() {
    val nvd = VulnItem.from(row("com.microsoft.emmx", "microsoft:edge_chromium",
      ranges = """[{"criteria":"cpe:2.3:a:microsoft:edge_chromium:*:*:*:*:*:*:*:*","endExcluding":"131.0"}]"""))
    val msrcNoBuild = VulnItem.from(row(linkPkg("com.microsoft.emmx", "msrc", "Microsoft Edge for Android"), "msrc:Microsoft Edge for Android",
      fix = """{"source":"MSRC"}"""))
    assertEquals(Affected.YES, VulnItem.dedupe(listOf(msrcNoBuild, nvd)).single().affected)
  }

  @Test fun linkKeyRoundTrip() {
    val p = linkPkg("com.example.app", "osv:PyPI", "django")
    assertEquals("com.example.app", parentPkg(p))
    assertEquals("com.example.app", parentPkg("com.example.app"))
  }
}
