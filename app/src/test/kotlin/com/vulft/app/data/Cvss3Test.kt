package com.vulft.app.data

import com.vulft.app.data.remote.Cvss3
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class Cvss3Test {
  @Test fun knownScores() {
    assertEquals(9.8, Cvss3.score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")!!, 0.0)
    assertEquals(5.9, Cvss3.score("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N")!!, 0.0)
    assertEquals(9.9, Cvss3.score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H")!!, 0.0)
    assertEquals(7.0, Cvss3.score("CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H")!!, 0.0)
    assertEquals(7.5, Cvss3.score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N")!!, 0.0)
    assertEquals(6.1, Cvss3.score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")!!, 0.0)
    assertEquals(0.0, Cvss3.score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")!!, 0.0)
  }

  @Test fun rejectsOtherVersions() {
    assertNull(Cvss3.score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"))
    assertNull(Cvss3.score("garbage"))
  }

  @Test fun msrcFixedBuildCheck() {
    // MSRC: installed build >= fixed build means patched.
    val fixed = "16.0.14334.21048"
    assert(Versions.compare("16.0.14334.21048", fixed) >= 0)
    assert(Versions.compare("16.0.14334.21100", fixed) >= 0)
    assert(Versions.compare("16.0.14332.20812", fixed) < 0)
  }
}
