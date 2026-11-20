package com.vulft.app.data

/** Forgiving version comparison for app versionName strings vs NVD CPE ranges. */
object Versions {
  private val tokenRegex = Regex("\\d+|[a-zA-Z]+")

  fun compare(a: String, b: String): Int {
    val ta = tokenRegex.findAll(a).map { it.value }.toList()
    val tb = tokenRegex.findAll(b).map { it.value }.toList()
    for (i in 0 until maxOf(ta.size, tb.size)) {
      val x = ta.getOrNull(i)
      val y = tb.getOrNull(i)
      if (x == null) return if (y!!.all(Char::isDigit) && y.trimStart('0').isEmpty()) 0 else -1
      if (y == null) return if (x.all(Char::isDigit) && x.trimStart('0').isEmpty()) 0 else 1
      val xn = x.all(Char::isDigit)
      val yn = y.all(Char::isDigit)
      val c = when {
        xn && yn -> x.trimStart('0').padStart(20, '0').compareTo(y.trimStart('0').padStart(20, '0'))
        xn -> 1 // 1.0.1 > 1.0.beta
        yn -> -1
        else -> x.compareTo(y, ignoreCase = true)
      }
      if (c != 0) return c
    }
    return 0
  }

  fun evaluate(installed: String?, ranges: List<CpeRange>): Affected {
    if (ranges.isEmpty() || installed.isNullOrBlank() || tokenRegex.find(installed) == null) return Affected.UNKNOWN
    var sawUnknown = false
    var sawKnown = false
    for (r in ranges) {
      val exact = r.criteria.split(":").getOrNull(5) ?: "*"
      val hasBounds = r.startIncluding != null || r.startExcluding != null || r.endIncluding != null || r.endExcluding != null
      if (!hasBounds) {
        // "*" = every version. "-" = NVD recorded no version information, so we can't tell.
        if (exact == "*") return Affected.YES
        if (exact == "-") { sawUnknown = true; continue }
        sawKnown = true
        if (compare(installed, exact) == 0) return Affected.YES
        continue
      }
      sawKnown = true
      var ok = true
      r.startIncluding?.let { if (compare(installed, it) < 0) ok = false }
      r.startExcluding?.let { if (compare(installed, it) <= 0) ok = false }
      r.endIncluding?.let { if (compare(installed, it) > 0) ok = false }
      r.endExcluding?.let { if (compare(installed, it) >= 0) ok = false }
      if (ok) return Affected.YES
    }
    // Only "unknown" when every entry lacked version info; a real range that excludes you means not affected.
    return if (sawUnknown && !sawKnown) Affected.UNKNOWN else Affected.NO
  }
}
