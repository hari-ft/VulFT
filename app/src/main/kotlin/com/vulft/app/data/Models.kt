package com.vulft.app.data

import androidx.room.ColumnInfo
import androidx.room.Embedded
import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json

val AppJson = Json { ignoreUnknownKeys = true; encodeDefaults = true; explicitNulls = false }

/** An installed app (or a manually-added product) that can be monitored. */
@Entity(tableName = "apps")
data class AppEntry(
  @PrimaryKey val packageName: String,
  val label: String,
  val versionName: String?,
  val category: String,
  val isSystem: Boolean,
  val installed: Boolean = true,
  val watched: Boolean = false,
  val cpeVendor: String? = null,
  val cpeProduct: String? = null,
  /** "builtin" (from KnownMappings), "manual" (chosen by user) or null. */
  val mappingSource: String? = null,
  val lastSynced: Long = 0,
  /** null = follow automatic monitoring; true/false = the user ticked/unticked it. */
  val watchChoice: Boolean? = null,
)

fun AppEntry.cpeKey(): String? =
  if (!cpeVendor.isNullOrBlank() && !cpeProduct.isNullOrBlank()) "$cpeVendor:$cpeProduct" else null

fun AppEntry.isManualProduct(): Boolean = packageName.startsWith(MANUAL_PREFIX)

const val MANUAL_PREFIX = "manual:"
const val DEVICE_OS_PKG = "device:android"

/**
 * Extra data-source links for an app are stored as hidden rows: "link:<parentPkg>|<vendor>|<product>".
 * They mirror the parent's label/version/watched state, so sync, CVE rows and alerts work unchanged.
 */
const val LINK_PREFIX = "link:"
fun linkPkg(parent: String, vendor: String, product: String) = "$LINK_PREFIX$parent|$vendor|$product"
fun isLinkPkg(pkg: String) = pkg.startsWith(LINK_PREFIX)
fun parentPkg(pkg: String) = if (isLinkPkg(pkg)) pkg.removePrefix(LINK_PREFIX).substringBefore('|') else pkg
fun AppEntry.isLink(): Boolean = isLinkPkg(packageName)

/** Where a monitored product's CVEs come from. Encoded in cpeVendor so the existing product key/join keeps working. */
enum class ProductSource(val label: String) { NVD("NVD"), OSV("OSV.dev"), ANDROID_OS("OSV.dev · Android bulletins"), MSRC("Microsoft MSRC") }

fun productSource(cpeVendor: String?, cpeProduct: String?): ProductSource = when {
  cpeVendor == "osv:Android" && cpeProduct?.startsWith("os:") == true -> ProductSource.ANDROID_OS
  cpeVendor?.startsWith("osv:") == true -> ProductSource.OSV
  cpeVendor == "msrc" -> ProductSource.MSRC
  else -> ProductSource.NVD
}

fun AppEntry.source(): ProductSource = productSource(cpeVendor, cpeProduct)

/** Human label for a product key, e.g. "PyPI · django", "Microsoft · Office LTSC 2021…", "google:chrome". */
fun productKeyLabel(cpeVendor: String?, cpeProduct: String?): String = when (productSource(cpeVendor, cpeProduct)) {
  ProductSource.OSV -> "${cpeVendor!!.removePrefix("osv:")} · $cpeProduct"
  ProductSource.ANDROID_OS -> "Android ${cpeProduct!!.removePrefix("os:")} · security bulletins"
  ProductSource.MSRC -> "Microsoft · $cpeProduct"
  ProductSource.NVD -> "$cpeVendor:$cpeProduct"
}

@Entity(tableName = "cves")
data class CveEntry(
  @PrimaryKey val id: String,
  val description: String,
  val published: String,
  val lastModified: String,
  val status: String,
  val cvssScore: Double?,
  /** CRITICAL, HIGH, MEDIUM, LOW, NONE (no score yet). */
  val severity: String,
  val cvssVersion: String?,
  val cvssVector: String?,
  val exploitabilityScore: Double?,
  val impactScore: Double?,
  /** Comma-separated CWE ids. */
  val cwes: String,
  /** JSON list of [CveReference]. */
  val referencesJson: String,
  val kev: Boolean = false,
  val kevDateAdded: String? = null,
  val kevDueDate: String? = null,
  val kevAction: String? = null,
  val kevRansomware: String? = null,
  val kevName: String? = null,
  val epss: Double? = null,
  val epssPercentile: Double? = null,
  /** Comma-separated vendor:product pairs NVD lists for this CVE. */
  @ColumnInfo(defaultValue = "") val affectedProducts: String = "",
  /** When a sync found NVD had changed this CVE (0 = never). */
  @ColumnInfo(defaultValue = "0") val updatedAt: Long = 0,
  /** What changed, e.g. "Severity High 7.5 → Critical 9.8 · Added to CISA KEV". */
  @ColumnInfo(defaultValue = "") val updateNote: String = "",
  /** false until the user opens the CVE after an update; drives the green "Updated" mark. */
  @ColumnInfo(defaultValue = "1") val updateSeen: Boolean = true,
  /** Databases that reported this CVE, e.g. "NVD,OSV,MSRC". */
  @ColumnInfo(defaultValue = "") val sources: String = "",
  /** Microsoft's Security Update Guide says it's exploited. */
  @ColumnInfo(defaultValue = "0") val msExploited: Boolean = false,
) {
  val exploited: Boolean get() = kev || msExploited
  fun sourceList(): List<String> = sources.split(',').filter { it.isNotBlank() }
  fun references(): List<CveReference> =
    runCatching { AppJson.decodeFromString(ListSerializer(CveReference.serializer()), referencesJson) }.getOrDefault(emptyList())
}

@Serializable data class CveReference(val url: String, val source: String? = null, val tags: List<String> = emptyList())

/** Version range from an NVD "cpeMatch" entry that applies to a product. */
@Serializable
data class CpeRange(
  val criteria: String,
  val startIncluding: String? = null,
  val startExcluding: String? = null,
  val endIncluding: String? = null,
  val endExcluding: String? = null,
) {
  fun describe(): String {
    val exact = criteria.split(":").getOrNull(5)
    val parts = buildList {
      startIncluding?.let { add(">= $it") }
      startExcluding?.let { add("> $it") }
      endIncluding?.let { add("<= $it") }
      endExcluding?.let { add("< $it") }
    }
    return when {
      parts.isNotEmpty() -> parts.joinToString(" and ")
      exact != null && exact != "*" && exact != "-" -> "= $exact"
      else -> "all versions"
    }
  }
}

/** Links a product (vendor:product) to a CVE. */
@Entity(tableName = "product_cves", primaryKeys = ["cpeKey", "cveId"], indices = [Index("cveId")])
data class ProductCve(
  val cpeKey: String,
  val cveId: String,
  /** JSON list of [CpeRange]. */
  val rangesJson: String,
  val firstSeen: Long,
  val alerted: Boolean = false,
  /** JSON [FixInfo] for OSV / Android / MSRC products (empty for NVD). */
  @ColumnInfo(defaultValue = "") val fixJson: String = "",
)

/** How a product fixes a CVE, and (for OSV/Android) whether the tracked version is affected. */
@Serializable
data class FixInfo(
  val source: String,
  /** Precomputed YES / NO / UNKNOWN (OSV and Android), or null to compute at runtime. */
  val affected: String? = null,
  /** e.g. "4.2.17", "Security patch 2024-08-01". */
  val fixedIn: List<String> = emptyList(),
  /** MSRC: KB article name/number, its URL and the fixed build number. */
  val kb: String? = null,
  val kbUrl: String? = null,
  val fixedBuild: String? = null,
  /** e.g. "platform/frameworks/base", "Remote Code Execution". */
  val note: String? = null,
)

fun parseFix(json: String): FixInfo? = if (json.isBlank()) null else runCatching { AppJson.decodeFromString(FixInfo.serializer(), json) }.getOrNull()

/** One row in the CVE list: a CVE affecting one watched app. */
data class CveRow(
  @Embedded val cve: CveEntry,
  val pkg: String,
  val appLabel: String,
  val appVersion: String?,
  val appCategory: String,
  val cpeKey: String,
  val ranges: String,
  val firstSeen: Long,
  val alerted: Boolean,
  val fixJson: String,
)

data class CpeCount(val cpeKey: String, val n: Int)

enum class Affected(val label: String) { YES("Your version is affected"), NO("Your version is not affected"), UNKNOWN("Version match unknown") }

/** A [CveRow] with the installed-version check done. */
data class VulnItem(val row: CveRow, val affected: Affected, val rangeList: List<CpeRange>, val fix: FixInfo? = null) {
  /** One card per app + CVE, even when several sources (NVD, MSRC, OSV) report it. */
  val key: String get() = "${parentPkg(row.pkg)}|${row.cve.id}"
  val appPkg: String get() = parentPkg(row.pkg)
  val cve: CveEntry get() = row.cve

  /** Short "how to fix" text for cards/emails. */
  fun fixSummary(): String? = fix?.let { f ->
    when {
      f.kb != null -> "Install ${kbLabel(f.kb)}" + (f.fixedBuild?.let { " (build $it)" } ?: "")
      f.fixedIn.isNotEmpty() -> "Fixed in " + f.fixedIn.joinToString(", ")
      else -> null
    }
  } ?: rangeList.takeIf { it.isNotEmpty() }?.let { "Vulnerable: " + it.joinToString("; ") { r -> r.describe() } }

  companion object {
    fun kbLabel(kb: String) = if (kb.all(Char::isDigit)) "KB$kb" else kb

    /**
     * Same CVE for the same app from several sources → keep the most precise answer:
     * a source with fix data (Microsoft build check, OSV version check) that decided YES/NO, then any decided answer, then the rest.
     */
    fun dedupe(items: List<VulnItem>): List<VulnItem> =
      items.groupBy { it.key }.map { (_, group) ->
        if (group.size == 1) group[0]
        else group.firstOrNull { it.fix != null && it.affected != Affected.UNKNOWN }
          ?: group.firstOrNull { it.affected != Affected.UNKNOWN }
          ?: group.first()
      }

    // Parsed JSON is cached by its text: the list re-maps ~16k rows on every database change, and
    // re-parsing every range/fix each time made the UI freeze for 1–2 s.
    private val rangeCache = Lru<String, List<CpeRange>>(40_000)
    private val fixCache = Lru<String, Optional<FixInfo>>(40_000)
    private class Optional<T>(val value: T?)

    private fun ranges(json: String): List<CpeRange> {
      if (json.isBlank() || json == "[]") return emptyList()
      return rangeCache[json] ?: runCatching { AppJson.decodeFromString(ListSerializer(CpeRange.serializer()), json) }
        .getOrDefault(emptyList()).also { rangeCache[json] = it }
    }

    private fun fix(json: String): FixInfo? {
      if (json.isBlank()) return null
      return (fixCache[json] ?: Optional(parseFix(json)).also { fixCache[json] = it }).value
    }

    fun from(row: CveRow): VulnItem {
      val ranges = ranges(row.ranges)
      val fix = fix(row.fixJson)
      val affected = when {
        fix?.affected != null -> runCatching { Affected.valueOf(fix.affected) }.getOrDefault(Affected.UNKNOWN)
        // MSRC: compare your build number with the fixed build.
        fix?.fixedBuild != null -> {
          val v = row.appVersion
          if (v.isNullOrBlank()) Affected.UNKNOWN else if (Versions.compare(v, fix.fixedBuild) >= 0) Affected.NO else Affected.YES
        }
        fix != null -> Affected.UNKNOWN
        else -> Versions.evaluate(row.appVersion, ranges)
      }
      return VulnItem(row, affected, ranges, fix)
    }
  }
}

/** Small thread-safe LRU cache (plain JVM, so it also works in unit tests). */
class Lru<K, V>(private val max: Int) {
  private val map = object : LinkedHashMap<K, V>(256, 0.75f, true) {
    override fun removeEldestEntry(eldest: MutableMap.MutableEntry<K, V>?) = size > max
  }
  @Synchronized operator fun get(key: K): V? = map[key]
  @Synchronized operator fun set(key: K, value: V) { map[key] = value }
}

object Severity {
  val all = listOf("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE")
  fun rank(s: String): Int = when (s) { "CRITICAL" -> 4; "HIGH" -> 3; "MEDIUM" -> 2; "LOW" -> 1; else -> 0 }
  fun label(s: String): String = if (s == "NONE") "Not scored" else s.lowercase().replaceFirstChar { it.uppercase() }
  fun fromScore(score: Double?): String = when {
    score == null -> "NONE"
    score >= 9.0 -> "CRITICAL"
    score >= 7.0 -> "HIGH"
    score >= 4.0 -> "MEDIUM"
    score > 0.0 -> "LOW"
    else -> "NONE"
  }
}
