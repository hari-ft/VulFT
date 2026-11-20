package com.vulft.app.data.remote

import com.vulft.app.data.AppJson
import com.vulft.app.data.CpeRange
import com.vulft.app.data.CveEntry
import com.vulft.app.data.CveReference
import com.vulft.app.data.Severity
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject

class HttpException(val code: Int, message: String) : IOException(message)

internal object Http {
  suspend fun get(url: String, headers: Map<String, String> = emptyMap()): String = withContext(Dispatchers.IO) {
    var attempt = 0
    while (true) {
      val conn = (URL(url).openConnection() as HttpURLConnection).apply {
        connectTimeout = 20_000
        readTimeout = 60_000
        setRequestProperty("User-Agent", "VulFT-Android/1.0")
        headers.forEach { (k, v) -> if (v.isNotBlank()) setRequestProperty(k, v) }
      }
      try {
        val code = conn.responseCode
        if (code in 200..299) return@withContext conn.inputStream.bufferedReader().use { it.readText() }
        // NVD returns 403/429/503 when rate limited – back off and retry.
        if ((code == 403 || code == 429 || code >= 500) && attempt < 3) {
          attempt++
          delay(6_000L * attempt)
          continue
        }
        val err = conn.errorStream?.bufferedReader()?.use { it.readText() }?.take(300) ?: ""
        throw HttpException(code, "HTTP $code from ${URL(url).host} $err")
      } finally {
        conn.disconnect()
      }
    }
    @Suppress("UNREACHABLE_CODE") error("unreachable")
  }

  fun enc(s: String): String = URLEncoder.encode(s, "UTF-8").replace("+", "%20")

  suspend fun postJson(url: String, body: String): String = withContext(Dispatchers.IO) {
    var attempt = 0
    while (true) {
      val conn = (URL(url).openConnection() as HttpURLConnection).apply {
        requestMethod = "POST"
        doOutput = true
        connectTimeout = 20_000
        readTimeout = 60_000
        setRequestProperty("User-Agent", "VulFT-Android/1.0")
        setRequestProperty("Content-Type", "application/json")
      }
      try {
        conn.outputStream.use { it.write(body.toByteArray()) }
        val code = conn.responseCode
        if (code in 200..299) return@withContext conn.inputStream.bufferedReader().use { it.readText() }
        if ((code == 429 || code >= 500) && attempt < 3) { attempt++; delay(3_000L * attempt); continue }
        throw HttpException(code, "HTTP $code from ${URL(url).host}")
      } finally {
        conn.disconnect()
      }
    }
    @Suppress("UNREACHABLE_CODE") error("unreachable")
  }
}

// ---- JSON helpers
internal fun JsonElement?.obj(): JsonObject? = this as? JsonObject
internal fun JsonElement?.arr(): JsonArray = (this as? JsonArray) ?: JsonArray(emptyList())
internal fun JsonElement?.str(): String? = (this as? JsonPrimitive)?.takeIf { it.isString || it.content != "null" }?.content
internal fun JsonElement?.dbl(): Double? = (this as? JsonPrimitive)?.let { it.doubleOrNull ?: it.content.toDoubleOrNull() }

data class NvdCve(val entry: CveEntry, val ranges: List<CpeRange>)
data class CpeSuggestion(val vendor: String, val product: String, val title: String, val part: String = "a") {
  val key: String get() = "$vendor:$product"
  val partLabel: String get() = when (part) { "o" -> "OS"; "h" -> "Hardware"; else -> "App" }
}

object NvdClient {
  private const val BASE = "https://services.nvd.nist.gov/rest/json"
  private const val PAGE = 2000
  private val nvdDate = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSxxx").withZone(ZoneOffset.UTC)

  /** All CVEs for vendor:product. If [modifiedSince] is set (<120 days ago) only changed CVEs are fetched. */
  suspend fun fetchCves(vendor: String, product: String, apiKey: String, modifiedSince: Instant?, onPage: suspend (Int, Int) -> Unit = { _, _ -> }): List<NvdCve> {
    val out = mutableListOf<NvdCve>()
    var start = 0
    while (true) {
      val url = buildString {
        append("$BASE/cves/2.0?virtualMatchString=").append(Http.enc("cpe:2.3:*:$vendor:$product"))
        append("&noRejected&resultsPerPage=$PAGE&startIndex=$start")
        if (modifiedSince != null) {
          append("&lastModStartDate=").append(Http.enc(nvdDate.format(modifiedSince)))
          append("&lastModEndDate=").append(Http.enc(nvdDate.format(Instant.now())))
        }
      }
      val root = AppJson.parseToJsonElement(Http.get(url, mapOf("apiKey" to apiKey))).jsonObject
      val total = (root["totalResults"] as? JsonPrimitive)?.intOrNull ?: 0
      val vulns = root["vulnerabilities"].arr()
      vulns.forEach { v -> v.obj()?.get("cve").obj()?.let { parseCve(it, vendor, product) }?.let(out::add) }
      onPage(minOf(start + vulns.size, total), total)
      start += vulns.size
      if (vulns.isEmpty() || start >= total) break
      delay(if (apiKey.isBlank()) 6_500 else 1_000) // NVD rate limits: 5 or 50 req / 30 s
    }
    return out
  }

  /**
   * Search every CVE NVD publishes. Results come newest first: NVD returns oldest first,
   * so we page backwards from the end. Pass [before] = previous page's olderStart to get older results.
   */
  suspend fun searchCves(q: CveQuery, apiKey: String, before: Int? = null, pageSize: Int = 50): CvePage {
    val idMatch = Regex("""(?i)^\s*(CVE-\d{4}-\d{4,})\s*$""").find(q.text)
    val base = buildString {
      append("$BASE/cves/2.0?noRejected")
      if (idMatch != null) append("&cveId=").append(idMatch.groupValues[1].uppercase())
      else if (q.text.isNotBlank()) append("&keywordSearch=").append(Http.enc(q.text.trim()))
      q.severity?.let { append("&cvssV3Severity=$it") }
      if (q.kevOnly) append("&hasKev")
      q.lastDays?.let { d ->
        val now = Instant.now()
        append("&pubStartDate=").append(Http.enc(nvdDate.format(now.minus(java.time.Duration.ofDays(d.toLong())))))
        append("&pubEndDate=").append(Http.enc(nvdDate.format(now)))
      }
    }
    val headers = mapOf("apiKey" to apiKey)
    var total = 0
    val end = before ?: run {
      val root = AppJson.parseToJsonElement(Http.get("$base&resultsPerPage=1&startIndex=0", headers)).jsonObject
      total = (root["totalResults"] as? JsonPrimitive)?.intOrNull ?: 0
      delay(if (apiKey.isBlank()) 6_500 else 700)
      total
    }
    if (end <= 0) return CvePage(emptyList(), null, total)
    val start = maxOf(0, end - pageSize)
    val root = AppJson.parseToJsonElement(Http.get("$base&resultsPerPage=${end - start}&startIndex=$start", headers)).jsonObject
    val items = root["vulnerabilities"].arr().mapNotNull { v -> v.obj()?.get("cve").obj()?.let { parseCve(it, null, null) } }
      .sortedByDescending { it.entry.published }
    total = (root["totalResults"] as? JsonPrimitive)?.intOrNull ?: total
    return CvePage(items.map { it.entry }, if (start > 0) start else null, total)
  }

  private fun parseCve(c: JsonObject, vendor: String?, product: String?): NvdCve? {
    val id = c["id"].str() ?: return null
    val status = c["vulnStatus"].str() ?: ""
    if (status.equals("Rejected", true)) return null
    val description = c["descriptions"].arr().mapNotNull { it.obj() }.let { list ->
      (list.firstOrNull { it["lang"].str() == "en" } ?: list.firstOrNull())?.get("value").str()
    } ?: ""

    var score: Double? = null; var severity: String? = null; var version: String? = null; var vector: String? = null
    var exploit: Double? = null; var impact: Double? = null
    val metrics = c["metrics"].obj()
    // CVSS v3 first: it's on almost every CVE and it's what NVD's severity filter (cvssV3Severity) uses.
    for ((key, ver) in listOf("cvssMetricV31" to "3.1", "cvssMetricV30" to "3.0", "cvssMetricV40" to "4.0", "cvssMetricV2" to "2.0")) {
      val list = metrics?.get(key).arr().mapNotNull { it.obj() }
      val m = list.firstOrNull { it["type"].str() == "Primary" } ?: list.firstOrNull() ?: continue
      val data = m["cvssData"].obj() ?: continue
      score = data["baseScore"].dbl()
      severity = data["baseSeverity"].str() ?: m["baseSeverity"].str()
      version = ver
      vector = data["vectorString"].str()
      exploit = m["exploitabilityScore"].dbl()
      impact = m["impactScore"].dbl()
      break
    }

    val cwes = c["weaknesses"].arr().flatMap { w -> w.obj()?.get("description").arr().mapNotNull { it.obj()?.get("value").str() } }
      .filter { it.startsWith("CWE-") }.distinct().joinToString(",")
    val refs = c["references"].arr().mapNotNull { r ->
      val o = r.obj() ?: return@mapNotNull null
      CveReference(o["url"].str() ?: return@mapNotNull null, o["source"].str(), o["tags"].arr().mapNotNull { it.str() })
    }

    val ranges = mutableListOf<CpeRange>()
    val products = LinkedHashSet<String>()
    c["configurations"].arr().forEach { cfg ->
      cfg.obj()?.get("nodes").arr().forEach { node ->
        node.obj()?.get("cpeMatch").arr().forEach { m ->
          val o = m.obj() ?: return@forEach
          if ((o["vulnerable"] as? JsonPrimitive)?.booleanOrNull == false) return@forEach
          val criteria = o["criteria"].str() ?: return@forEach
          val parts = criteria.split(":")
          if (parts.size > 4) products += "${parts[3]}:${parts[4]}"
          if (vendor != null && parts.getOrNull(3).equals(vendor, true) && parts.getOrNull(4).equals(product, true)) {
            ranges += CpeRange(criteria, o["versionStartIncluding"].str(), o["versionStartExcluding"].str(), o["versionEndIncluding"].str(), o["versionEndExcluding"].str())
          }
        }
      }
    }

    val entry = CveEntry(
      id = id,
      description = description,
      published = c["published"].str() ?: "",
      lastModified = c["lastModified"].str() ?: "",
      status = status,
      cvssScore = score,
      severity = severity?.uppercase() ?: Severity.fromScore(score),
      cvssVersion = version,
      cvssVector = vector,
      exploitabilityScore = exploit,
      impactScore = impact,
      cwes = cwes,
      referencesJson = AppJson.encodeToString(ListSerializer(CveReference.serializer()), refs),
      kev = c["cisaExploitAdd"].str() != null,
      kevDateAdded = c["cisaExploitAdd"].str(),
      kevDueDate = c["cisaActionDue"].str(),
      kevAction = c["cisaRequiredAction"].str(),
      kevName = c["cisaVulnerabilityName"].str(),
      affectedProducts = products.joinToString(","),
      sources = "NVD",
    )
    return NvdCve(entry, ranges.distinct())
  }

  /** Search the whole NVD CPE dictionary (one page). [vendor] limits results to one vendor. */
  suspend fun searchProductsPage(keyword: String, apiKey: String, start: Int = 0, vendor: String? = null): CpePage {
    val url = "$BASE/cpes/2.0?keywordSearch=${Http.enc(keyword)}&resultsPerPage=1000&startIndex=$start"
    val root = AppJson.parseToJsonElement(Http.get(url, mapOf("apiKey" to apiKey))).jsonObject
    val total = (root["totalResults"] as? JsonPrimitive)?.intOrNull ?: 0
    val products = root["products"].arr()
    val items = products.mapNotNull { p ->
      val cpe = p.obj()?.get("cpe").obj() ?: return@mapNotNull null
      val parts = cpe["cpeName"].str()?.split(":") ?: return@mapNotNull null
      if (parts.size < 5) return@mapNotNull null
      if (vendor != null && !parts[3].equals(vendor, true)) return@mapNotNull null
      val title = cpe["titles"].arr().mapNotNull { it.obj() }.let { t -> (t.firstOrNull { it["lang"].str() == "en" } ?: t.firstOrNull())?.get("title").str() } ?: ""
      CpeSuggestion(parts[3], parts[4], cleanTitle(title, parts[3], parts[4]), parts[2])
    }.distinctBy { it.key }
    val next = start + products.size
    return CpePage(items, if (products.isNotEmpty() && next < total) next else null, total)
  }

  suspend fun searchProducts(keyword: String, apiKey: String): List<CpeSuggestion> = searchProductsPage(keyword, apiKey).items

  /** vendor:product pairs listed as vulnerable in one CVE. */
  suspend fun productsForCve(cveId: String, apiKey: String): List<Pair<String, String>> {
    val root = AppJson.parseToJsonElement(Http.get("$BASE/cves/2.0?cveId=${Http.enc(cveId)}", mapOf("apiKey" to apiKey))).jsonObject
    val cve = root["vulnerabilities"].arr().firstOrNull()?.obj()?.get("cve").obj() ?: return emptyList()
    val out = LinkedHashSet<Pair<String, String>>()
    cve["configurations"].arr().forEach { cfg ->
      cfg.obj()?.get("nodes").arr().forEach { node ->
        node.obj()?.get("cpeMatch").arr().forEach { m ->
          val o = m.obj() ?: return@forEach
          if ((o["vulnerable"] as? JsonPrimitive)?.booleanOrNull != true) return@forEach
          val parts = o["criteria"].str()?.split(":") ?: return@forEach
          if (parts.size > 4) out += parts[3] to parts[4]
        }
      }
    }
    return out.toList()
  }

  private fun cleanTitle(title: String, vendor: String, product: String): String {
    val t = title.replace(Regex("""\s+v?\d[\w.\-]*.*$"""), "").trim()
    return t.ifBlank { "${vendor.replace('_', ' ')} ${product.replace('_', ' ')}" }
  }
}

data class CveQuery(val text: String = "", val severity: String? = null, val kevOnly: Boolean = false, val lastDays: Int? = null)
data class CvePage(val items: List<CveEntry>, val olderStart: Int?, val total: Int)

data class CpePage(val items: List<CpeSuggestion>, val nextStart: Int?, val total: Int)

data class KevProduct(val vendor: String, val product: String, val count: Int, val cveIds: List<String>, val latest: String, val ransomware: Boolean) {
  val key: String get() = "kev:$vendor|$product"
}

data class KevEntry(val cveId: String, val dateAdded: String?, val dueDate: String?, val action: String?, val ransomware: String?, val name: String?, val vendorProject: String = "", val product: String = "", val shortDescription: String = "") {
  /** A CVE record from the KEV catalog alone (used when NVD/MSRC don't return it in a search). */
  fun toEntry(): CveEntry = CveEntry(
    id = cveId,
    description = listOfNotNull(name, shortDescription.ifBlank { null }).joinToString("\n\n"),
    published = dateAdded ?: "",
    lastModified = dateAdded ?: "",
    status = "CISA KEV",
    cvssScore = null,
    severity = "NONE",
    cvssVersion = null, cvssVector = null, exploitabilityScore = null, impactScore = null,
    cwes = "",
    referencesJson = AppJson.encodeToString(ListSerializer(CveReference.serializer()),
      listOf(CveReference("https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=$cveId", "CISA", listOf("KEV")))),
    kev = true, kevDateAdded = dateAdded, kevDueDate = dueDate, kevAction = action, kevRansomware = ransomware, kevName = name,
    affectedProducts = "",
    sources = "CISA KEV",
  )
}

object KevClient {
  private const val URL_KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
  suspend fun fetch(): List<KevEntry> {
    val root = AppJson.parseToJsonElement(Http.get(URL_KEV)).jsonObject
    return root["vulnerabilities"].arr().mapNotNull { v ->
      val o = v.obj() ?: return@mapNotNull null
      KevEntry(o["cveID"].str() ?: return@mapNotNull null, o["dateAdded"].str(), o["dueDate"].str(), o["requiredAction"].str(), o["knownRansomwareCampaignUse"].str(), o["vulnerabilityName"].str(),
        o["vendorProject"].str() ?: "", o["product"].str() ?: "", o["shortDescription"].str() ?: "")
    }
  }

  /** Every distinct product in the KEV catalog, most-exploited first. */
  fun products(entries: List<KevEntry>): List<KevProduct> =
    entries.filter { it.vendorProject.isNotBlank() }.groupBy { it.vendorProject.trim() to it.product.trim() }.map { (k, list) ->
      val sorted = list.sortedByDescending { it.dateAdded ?: "" }
      KevProduct(k.first, k.second, list.size, sorted.map { it.cveId }, sorted.first().dateAdded ?: "", list.any { it.ransomware == "Known" })
    }.sortedWith(compareByDescending<KevProduct> { it.count }.thenBy { it.vendor.lowercase() })
}

object EpssClient {
  /** Returns cve -> (epss, percentile). */
  suspend fun fetch(cveIds: List<String>): Map<String, Pair<Double, Double>> {
    val out = mutableMapOf<String, Pair<Double, Double>>()
    cveIds.distinct().chunked(100).forEach { chunk ->
      val root = AppJson.parseToJsonElement(Http.get("https://api.first.org/data/v1/epss?cve=${chunk.joinToString(",")}")).jsonObject
      root["data"].arr().forEach { d ->
        val o = d.obj() ?: return@forEach
        val id = o["cve"].str() ?: return@forEach
        val e = o["epss"].dbl() ?: return@forEach
        out[id] = e to (o["percentile"].dbl() ?: 0.0)
      }
    }
    return out
  }
}

data class GhAdvisory(val ghsaId: String, val summary: String, val severity: String?, val url: String, val packages: List<String>)

object GithubAdvisoryClient {
  suspend fun forCve(cveId: String, token: String): List<GhAdvisory> {
    val body = Http.get(
      "https://api.github.com/advisories?cve_id=${Http.enc(cveId)}",
      mapOf("Accept" to "application/vnd.github+json", "X-GitHub-Api-Version" to "2022-11-28", "Authorization" to if (token.isBlank()) "" else "Bearer $token"),
    )
    return AppJson.parseToJsonElement(body).jsonArray.mapNotNull { a ->
      val o = a.obj() ?: return@mapNotNull null
      GhAdvisory(
        ghsaId = o["ghsa_id"].str() ?: return@mapNotNull null,
        summary = o["summary"].str() ?: "",
        severity = o["severity"].str(),
        url = o["html_url"].str() ?: "",
        packages = o["vulnerabilities"].arr().mapNotNull { v ->
          val vo = v.obj() ?: return@mapNotNull null
          val pkg = vo["package"].obj()
          val name = "${pkg?.get("ecosystem").str() ?: ""}/${pkg?.get("name").str() ?: ""}"
          val range = vo["vulnerable_version_range"].str()
          val fixed = vo["first_patched_version"].str()
          buildString { append(name); range?.let { append("  $it") }; fixed?.let { append("  (fixed in $it)") } }
        },
      )
    }
  }
}
