package com.vulft.app.data.remote

import com.vulft.app.data.AppJson
import com.vulft.app.data.CveEntry
import com.vulft.app.data.CveReference
import com.vulft.app.data.Severity
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import kotlin.math.floor
import kotlin.math.min
import kotlin.math.pow
import kotlin.math.roundToLong
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.delay
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonObject

// ============================================================================ CVSS v3.x base score

/** Computes the CVSS v3.0/3.1 base score from a vector (OSV gives vectors, not scores). */
object Cvss3 {
  fun score(vector: String): Double? {
    if (!vector.startsWith("CVSS:3")) return null
    val m = vector.split('/').drop(1).mapNotNull { p -> p.split(':').takeIf { it.size == 2 }?.let { it[0] to it[1] } }.toMap()
    val scopeChanged = m["S"] == "C"
    val av = when (m["AV"]) { "N" -> 0.85; "A" -> 0.62; "L" -> 0.55; "P" -> 0.2; else -> return null }
    val ac = when (m["AC"]) { "L" -> 0.77; "H" -> 0.44; else -> return null }
    val pr = when (m["PR"]) { "N" -> 0.85; "L" -> if (scopeChanged) 0.68 else 0.62; "H" -> if (scopeChanged) 0.5 else 0.27; else -> return null }
    val ui = when (m["UI"]) { "N" -> 0.85; "R" -> 0.62; else -> return null }
    fun cia(k: String) = when (m[k]) { "H" -> 0.56; "L" -> 0.22; "N" -> 0.0; else -> null }
    val c = cia("C") ?: return null; val i = cia("I") ?: return null; val a = cia("A") ?: return null
    val iss = 1 - (1 - c) * (1 - i) * (1 - a)
    val impact = if (scopeChanged) 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).pow(15) else 6.42 * iss
    val exploitability = 8.22 * av * ac * pr * ui
    if (impact <= 0) return 0.0
    return roundUp(min(if (scopeChanged) 1.08 * (impact + exploitability) else impact + exploitability, 10.0))
  }

  private fun roundUp(x: Double): Double {
    val i = (x * 100_000).roundToLong()
    return if (i % 10_000 == 0L) i / 100_000.0 else (floor(i / 10_000.0) + 1) / 10.0
  }
}

// ============================================================================ OSV.dev

object OsvClient {
  private const val BASE = "https://api.osv.dev/v1"

  /** Ecosystems offered in the catalog (OSV supports more; these cover most users). */
  val ecosystems = listOf(
    "PyPI", "npm", "Maven", "Go", "NuGet", "crates.io", "RubyGems", "Packagist", "Pub", "Hex", "CRAN",
    "SwiftURL", "GitHub Actions", "Debian:12", "Ubuntu:24.04:LTS", "Alpine:v3.20", "Linux",
  )

  /** AOSP components that appear in Android Security Bulletins (checked against the phone's patch level). */
  val androidComponents = listOf(
    "platform/frameworks/base", "platform/frameworks/av", "platform/frameworks/native", "platform/system/core",
    "platform/packages/modules/Bluetooth", "platform/packages/apps/Settings", "platform/packages/modules/Wifi",
    "platform/packages/providers/MediaProvider", "platform/packages/modules/Permission", "platform/packages/services/Telephony",
    "platform/packages/modules/Connectivity", "platform/external/skia", "platform/system/netd", "platform/packages/apps/Launcher3",
    "platform/frameworks/opt/telephony", "platform/system/sepolicy", "platform/packages/modules/StatsD", "platform/packages/modules/adb",
    "platform/external/aac", "platform/external/libhevc", "platform/packages/modules/DnsResolver", "platform/system/nfc",
    "platform/packages/apps/Nfc", "platform/external/freetype", "platform/external/sqlite", "platform/packages/apps/Contacts",
    "platform/packages/modules/Virtualization", "platform/hardware/interfaces", "platform/packages/apps/CertInstaller",
  )

  /** All vulnerabilities for a package (optionally only those affecting [version]), following page tokens. */
  suspend fun query(ecosystem: String, name: String, version: String? = null): List<JsonObject> {
    val out = mutableListOf<JsonObject>()
    var token: String? = null
    do {
      val body = buildJsonObject {
        putJsonObject("package") { put("name", name); put("ecosystem", ecosystem) }
        if (!version.isNullOrBlank()) put("version", version)
        token?.let { put("page_token", it) }
      }
      val root = AppJson.parseToJsonElement(Http.postJson("$BASE/query", body.toString())).jsonObject
      root["vulns"].arr().mapNotNullTo(out) { it.obj() }
      token = root["next_page_token"].str()
      if (token != null) delay(300)
    } while (token != null)
    return out
  }

  suspend fun vuln(id: String): JsonObject = AppJson.parseToJsonElement(Http.get("$BASE/vulns/${Http.enc(id)}")).jsonObject

  /** The CVE id if OSV knows one (so OSV, NVD and MSRC records merge), else the OSV id. */
  fun primaryId(v: JsonObject): String =
    (listOfNotNull(v["id"].str()) + v["aliases"].arr().mapNotNull { it.str() }).firstOrNull { it.startsWith("CVE-") } ?: v["id"].str()!!

  fun toEntry(v: JsonObject): CveEntry? {
    v["id"].str() ?: return null
    if (v["withdrawn"].str() != null) return null
    val summary = v["summary"].str().orEmpty()
    val details = v["details"].str().orEmpty()
    val description = when {
      summary.isNotBlank() && details.isNotBlank() && !details.startsWith(summary) -> "$summary\n\n$details"
      details.isNotBlank() -> details
      else -> summary
    }.take(4000)

    var score: Double? = null; var vector: String? = null; var version: String? = null
    v["severity"].arr().mapNotNull { it.obj() }.let { sev ->
      sev.firstOrNull { it["type"].str() == "CVSS_V3" }?.get("score").str()?.let { vector = it; score = Cvss3.score(it); version = it.substringAfter("CVSS:").substringBefore('/') }
      if (vector == null) sev.firstOrNull { it["type"].str() == "CVSS_V4" }?.get("score").str()?.let { vector = it; version = "4.0" }
    }
    val textSeverity = (v["database_specific"].obj()?.get("severity").str()
      ?: v["affected"].arr().firstNotNullOfOrNull { it.obj()?.get("ecosystem_specific").obj()?.get("severity").str() })
      ?.uppercase()?.let { if (it == "MODERATE") "MEDIUM" else it }
      ?.takeIf { it in Severity.all }

    val refs = v["references"].arr().mapNotNull { r ->
      val o = r.obj() ?: return@mapNotNull null
      CveReference(o["url"].str() ?: return@mapNotNull null, "OSV", listOfNotNull(o["type"].str()))
    } + CveReference("https://osv.dev/vulnerability/${v["id"].str()}", "OSV", listOf("OSV"))
    val cwes = v["database_specific"].obj()?.get("cwe_ids").arr().mapNotNull { it.str() }.joinToString(",")
    val products = v["affected"].arr().mapNotNull { a ->
      val p = a.obj()?.get("package").obj() ?: return@mapNotNull null
      "osv:${p["ecosystem"].str()}:${p["name"].str()}"
    }.distinct().joinToString(",")

    return CveEntry(
      id = primaryId(v),
      description = description,
      published = v["published"].str() ?: v["modified"].str() ?: "",
      lastModified = v["modified"].str() ?: "",
      status = "OSV ${v["id"].str()}",
      cvssScore = score,
      severity = if (score != null) Severity.fromScore(score) else textSeverity ?: "NONE",
      cvssVersion = version,
      cvssVector = vector,
      exploitabilityScore = null,
      impactScore = null,
      cwes = cwes,
      referencesJson = AppJson.encodeToString(ListSerializer(CveReference.serializer()), refs),
      affectedProducts = products,
      sources = "OSV",
    )
  }

  /** Fixed versions OSV lists for one package in a record. */
  fun fixedVersions(v: JsonObject, ecosystem: String, name: String): List<String> =
    v["affected"].arr().mapNotNull { it.obj() }
      .filter { a -> a["package"].obj()?.let { it["ecosystem"].str() == ecosystem && it["name"].str() == name } == true }
      .flatMap { a -> a["ranges"].arr().flatMap { r -> r.obj()?.get("events").arr().mapNotNull { e -> e.obj()?.get("fixed").str() } } }
      .filter { it.length < 40 } // skip git commit hashes
      .distinct()

  /**
   * Android bulletins: the security patch level that fixes [component] on Android [release], e.g. "2024-08-01".
   * Null if the record doesn't cover that release.
   */
  fun androidFixSpl(v: JsonObject, component: String, release: String): String? =
    v["affected"].arr().mapNotNull { it.obj() }
      .filter { a -> a["package"].obj()?.get("name").str() == component && a["versions"].arr().any { it.str() == release } }
      .firstNotNullOfOrNull { a ->
        a["ecosystem_specific"].obj()?.get("spl").str()
          ?: a["ranges"].arr().firstNotNullOfOrNull { r -> r.obj()?.get("events").arr().firstNotNullOfOrNull { it.obj()?.get("fixed").str()?.substringAfter(':') } }
      }

  /** For the detail screen: package fixed versions, following GHSA/PYSEC aliases of a CVE record. */
  suspend fun fixedVersionsFor(cveId: String): List<String> {
    val records = mutableListOf<JsonObject>()
    val first = runCatching { vuln(cveId) }.getOrNull() ?: return emptyList()
    records += first
    first["aliases"].arr().mapNotNull { it.str() }.filter { !it.startsWith("CVE-") }.take(4).forEach { alias ->
      runCatching { vuln(alias) }.getOrNull()?.let(records::add)
    }
    return records.flatMap { r ->
      r["affected"].arr().mapNotNull { it.obj() }.mapNotNull { a ->
        val p = a["package"].obj() ?: return@mapNotNull null
        val eco = p["ecosystem"].str() ?: return@mapNotNull null
        val fixed = a["ranges"].arr().flatMap { rr -> rr.obj()?.get("events").arr().mapNotNull { e -> e.obj()?.get("fixed").str() } }
          .filter { it.length < 40 }.distinct()
        "$eco · ${p["name"].str()}" + if (fixed.isNotEmpty()) " — fixed in ${fixed.joinToString(", ")}" else " — no fixed version listed"
      }
    }.distinct()
  }
}

// ============================================================================ Microsoft Security Update Guide

data class MsrcProduct(val name: String, val family: String)

data class MsrcRow(
  val cve: String, val product: String, val severity: String?, val impact: String?, val baseScore: Double?, val vector: String?,
  val kb: String?, val kbUrl: String?, val fixedBuild: String?, val cwes: List<String>, val releaseDate: String, val initialReleaseDate: String?,
)

data class MsrcVuln(val cve: String, val title: String, val description: String, val exploited: Boolean, val latestRevision: String?, val published: String?)

object MsrcClient {
  private const val BASE = "https://api.msrc.microsoft.com/sug/v2.0/en-US"
  private val odataDate = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'").withZone(ZoneOffset.UTC)

  private fun q(s: String) = s.replace("'", "''")

  private suspend fun pages(firstUrl: String, maxPages: Int = 40): List<JsonObject> {
    val out = mutableListOf<JsonObject>()
    var url: String? = firstUrl
    var n = 0
    while (url != null && n < maxPages) {
      val root = AppJson.parseToJsonElement(Http.get(url, mapOf("Accept" to "application/json"))).jsonObject
      root["value"].arr().mapNotNullTo(out) { it.obj() }
      url = root["@odata.nextLink"].str()
      n++
    }
    return out
  }

  /** Product names containing [text] (case-sensitive on Microsoft's side, so we also try a capitalised form). */
  suspend fun searchProducts(text: String): List<MsrcProduct> {
    val since = odataDate.format(Instant.now().minus(Duration.ofDays(400)))
    val variants = listOf(text.trim(), text.trim().replaceFirstChar { it.uppercase() }).distinct().filter { it.isNotBlank() }
    val found = LinkedHashMap<String, MsrcProduct>()
    for (t in variants) {
      val filter = "contains(product,'${q(t)}') and releaseDate gt $since"
      pages("$BASE/affectedProduct?\$orderby=releaseDate%20desc&\$filter=${Http.enc(filter)}", maxPages = 2).forEach { o ->
        val name = o["product"].str() ?: return@forEach
        found.getOrPut(name) { MsrcProduct(name, o["productFamily"].str() ?: "") }
      }
    }
    return found.values.sortedBy { it.name }
  }

  /** CVE rows for one product released/revised after [since]. */
  suspend fun productRows(product: String, since: Instant): List<MsrcRow> {
    val filter = "product eq '${q(product)}' and releaseDate gt ${odataDate.format(since)}"
    return pages("$BASE/affectedProduct?\$orderby=releaseDate%20desc&\$filter=${Http.enc(filter)}").mapNotNull { o ->
      val kbs = o["kbArticles"].arr().mapNotNull { it.obj() }
      val kb = kbs.firstOrNull { !it["fixedBuildNumber"].str().isNullOrBlank() } ?: kbs.firstOrNull()
      MsrcRow(
        cve = o["cveNumber"].str() ?: return@mapNotNull null,
        product = o["product"].str() ?: product,
        severity = o["severity"].str(),
        impact = o["impact"].str(),
        baseScore = o["baseScore"].dbl(),
        vector = o["vectorString"].str(),
        kb = kb?.get("articleName").str(),
        kbUrl = kb?.get("articleUrl").str() ?: kb?.get("downloadUrl").str(),
        fixedBuild = kb?.get("fixedBuildNumber").str()?.takeIf { it.isNotBlank() },
        cwes = o["cweList"].arr().mapNotNull { it.str()?.substringBefore(':')?.trim() },
        releaseDate = o["releaseDate"].str() ?: "",
        initialReleaseDate = o["initialReleaseDate"].str(),
      )
    }
  }

  /** Title, description and exploited flag, 10 CVEs per request (Microsoft rejects longer OR filters). */
  suspend fun details(cves: List<String>, onBatch: suspend (Int) -> Unit = {}): Map<String, MsrcVuln> = kotlinx.coroutines.coroutineScope {
    val out = java.util.concurrent.ConcurrentHashMap<String, MsrcVuln>()
    var done = 0
    // 4 requests at a time: big products (Windows, Office) have hundreds of CVEs.
    cves.distinct().chunked(10).chunked(4).forEach { group ->
      group.map { chunk ->
        async {
          val filter = chunk.joinToString(" or ") { "cveNumber eq '${q(it)}'" }
          runCatching { pages("$BASE/vulnerability?\$filter=${Http.enc(filter)}", maxPages = 1) }.getOrDefault(emptyList()).forEach { o ->
            val id = o["cveNumber"].str() ?: return@forEach
            out[id] = MsrcVuln(
              cve = id,
              title = o["cveTitle"].str() ?: "",
              description = (o["unformattedDescription"].str() ?: o["description"].str() ?: "").replace(Regex("<[^>]+>"), "").trim(),
              exploited = o["exploited"].str().equals("Yes", true),
              latestRevision = o["latestRevisionDate"].str(),
              published = o["releaseDate"].str(),
            )
          }
        }
      }.awaitAll()
      done += group.sumOf { it.size }
      onBatch(done)
    }
    out
  }

  /** CVEs whose Microsoft title contains [text] (newest first), or the one CVE with that id. */
  suspend fun searchVulnerabilities(text: String? = null, cveId: String? = null, max: Int = 100): List<CveEntry> {
    val filters = when {
      cveId != null -> listOf("cveNumber eq '${q(cveId)}'")
      // Microsoft's search is case-sensitive and titles are Title Case ("Outlook Spoofing Vulnerability"),
      // so try as typed, first letter capitalised, and every word capitalised.
      text != null -> text.trim().let { t ->
        listOf(t, t.replaceFirstChar { it.uppercase() }, t.split(Regex("\\s+")).joinToString(" ") { w -> w.replaceFirstChar { it.uppercase() } })
      }.distinct().filter { it.isNotBlank() }.map { "contains(cveTitle,'${q(it)}')" }
      else -> return emptyList()
    }
    val out = LinkedHashMap<String, CveEntry>()
    for (f in filters) {
      pages("$BASE/vulnerability?\$orderby=releaseDate%20desc&\$filter=${Http.enc(f)}", maxPages = 1).forEach { o ->
        val id = o["cveNumber"].str() ?: return@forEach
        if (out.size >= max || id in out) return@forEach
        val score = o["baseScore"].dbl()?.takeIf { it > 0 }
        val vector = o["vectorString"].str()
        val title = o["cveTitle"].str().orEmpty()
        val desc = (o["unformattedDescription"].str() ?: o["description"].str() ?: "").replace(Regex("<[^>]+>"), "").trim()
        out[id] = CveEntry(
          id = id,
          description = listOf(title, desc).filter { it.isNotBlank() }.distinct().joinToString("\n\n"),
          published = o["releaseDate"].str() ?: "",
          lastModified = o["latestRevisionDate"].str() ?: o["releaseDate"].str() ?: "",
          status = "Microsoft ${o["severity"].str() ?: ""}".trim(),
          cvssScore = score,
          severity = if (score != null) Severity.fromScore(score) else when (o["severity"].str()) { "Critical" -> "CRITICAL"; "Important" -> "HIGH"; "Moderate" -> "MEDIUM"; "Low" -> "LOW"; else -> "NONE" },
          cvssVersion = vector?.substringAfter("CVSS:", "")?.substringBefore('/')?.ifBlank { null },
          cvssVector = vector?.split('/')?.filterNot { it.startsWith("E:") || it.startsWith("RL:") || it.startsWith("RC:") }?.joinToString("/"),
          exploitabilityScore = null,
          impactScore = null,
          cwes = o["cweList"].arr().mapNotNull { it.str()?.substringBefore(':')?.trim() }.joinToString(","),
          referencesJson = AppJson.encodeToString(ListSerializer(CveReference.serializer()),
            listOf(CveReference("https://msrc.microsoft.com/update-guide/vulnerability/$id", "MSRC", listOf("Microsoft")))),
          sources = "MSRC",
          msExploited = o["exploited"].str().equals("Yes", true),
        )
      }
    }
    return out.values.toList()
  }

  fun toEntry(row: MsrcRow, info: MsrcVuln?): CveEntry {
    val score = row.baseScore?.takeIf { it > 0 }
    val description = listOf(info?.title.orEmpty(), info?.description.orEmpty()).filter { it.isNotBlank() }.distinct().joinToString("\n\n")
      .ifBlank { "${row.impact ?: "Vulnerability"} in ${row.product}" }
    return CveEntry(
      id = row.cve,
      description = description,
      published = info?.published ?: row.initialReleaseDate ?: row.releaseDate,
      lastModified = info?.latestRevision ?: row.releaseDate,
      status = "Microsoft ${row.severity ?: ""}".trim(),
      cvssScore = score,
      severity = if (score != null) Severity.fromScore(score) else when (row.severity) { "Critical" -> "CRITICAL"; "Important" -> "HIGH"; "Moderate" -> "MEDIUM"; "Low" -> "LOW"; else -> "NONE" },
      cvssVersion = row.vector?.substringAfter("CVSS:", "")?.substringBefore('/')?.ifBlank { null },
      cvssVector = row.vector?.split('/')?.filterNot { it.startsWith("E:") || it.startsWith("RL:") || it.startsWith("RC:") }?.joinToString("/"),
      exploitabilityScore = null,
      impactScore = null,
      cwes = row.cwes.joinToString(","),
      referencesJson = AppJson.encodeToString(ListSerializer(CveReference.serializer()),
        listOf(CveReference("https://msrc.microsoft.com/update-guide/vulnerability/${row.cve}", "MSRC", listOf("Microsoft"))) +
          listOfNotNull(row.kbUrl?.let { CveReference(it, "MSRC", listOf("Fix")) })),
      affectedProducts = "msrc:${row.product}",
      sources = "MSRC",
      msExploited = info?.exploited == true,
    )
  }
}
