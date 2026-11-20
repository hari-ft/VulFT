package com.vulft.app.data

import android.content.Context
import androidx.room.withTransaction
import com.vulft.app.data.remote.CpePage
import com.vulft.app.data.remote.CvePage
import com.vulft.app.data.remote.CveQuery
import com.vulft.app.data.remote.CpeSuggestion
import com.vulft.app.data.remote.KevProduct
import kotlinx.coroutines.delay
import com.vulft.app.data.remote.EpssClient
import com.vulft.app.data.remote.KevClient
import com.vulft.app.data.remote.MsrcClient
import com.vulft.app.data.remote.MsrcProduct
import com.vulft.app.data.remote.NvdClient
import com.vulft.app.data.remote.OsvClient
import java.time.Duration
import java.time.Instant
import kotlinx.coroutines.flow.Flow
import kotlinx.serialization.builtins.ListSerializer

class VulnRepository(private val context: Context, private val db: AppDatabase, private val settings: SettingsStore) {
  private val dao = db.dao()

  val apps: Flow<List<AppEntry>> = dao.appsFlow()
  val cveCounts: Flow<List<CpeCount>> = dao.countsFlow()
  val rows: Flow<List<CveRow>> = dao.rowsFlow()

  fun cve(id: String) = dao.cveFlow(id)
  fun rowsForCve(id: String) = dao.rowsForCve(id)
  /** One item per app + CVE (sources merged). */
  suspend fun currentItems(): List<VulnItem> = VulnItem.dedupe(dao.rows().map(VulnItem::from))
  /** Every source's row separately (for alert bookkeeping). */
  suspend fun currentItemsRaw(): List<VulnItem> = dao.rows().map(VulnItem::from)

  /** Re-scan installed apps, keeping watch/mapping choices. New apps get built-in NVD and Microsoft links if known. */
  suspend fun refreshInstalledApps() {
    val scanned = InstalledApps.scan(context)
    val all = dao.allApps()
    val existing = all.filterNot { it.isLink() }.associateBy { it.packageName }
    val existingLinks = all.filter { it.isLink() }
    val scannedPkgs = scanned.map { it.packageName }.toSet()
    val updated = scanned.map { s ->
      val old = existing[s.packageName]
      val known = KnownMappings.map[s.packageName]
      if (old != null) {
        val base = old.copy(label = s.label, versionName = s.versionName, category = s.category, isSystem = s.isSystem, installed = true)
        // Apps with no product yet pick up a built-in mapping added in a newer app version.
        if (base.cpeVendor == null && base.mappingSource == null && known != null)
          base.copy(cpeVendor = known.first, cpeProduct = known.second, mappingSource = "builtin")
        else base
      } else {
        AppEntry(s.packageName, s.label, s.versionName, s.category, s.isSystem, installed = true,
          cpeVendor = known?.first, cpeProduct = known?.second, mappingSource = known?.let { "builtin" })
      }
    }
    val gone = existing.values.filter { it.packageName !in scannedPkgs && !it.isManualProduct() && it.packageName != DEVICE_OS_PKG && it.installed }
      .map { it.copy(installed = false, watched = false) }

    // Built-in Microsoft (MSRC) links for Microsoft's Android apps.
    val linkPkgs = existingLinks.map { it.packageName }.toSet()
    val newLinks = scanned.mapNotNull { s ->
      val product = KnownMappings.msrc[s.packageName] ?: return@mapNotNull null
      val pkg = linkPkg(s.packageName, "msrc", product)
      if (pkg in linkPkgs) null else AppEntry(pkg, s.label, s.versionName, s.category, s.isSystem, cpeVendor = "msrc", cpeProduct = product, mappingSource = "builtin")
    }
    val parentsAfter = (updated + gone).associateBy { it.packageName }
    val linkCountByParent = (existingLinks + newLinks).groupingBy { parentPkg(it.packageName) }.eachCount()
    val parents = updated.map { withAutoWatch(it, linkCountByParent[it.packageName] ?: 0) } + gone
    val parentState = parents.associateBy { it.packageName }
    val links = (existingLinks + newLinks).map { l -> mirrorParent(l, parentState[parentPkg(l.packageName)] ?: parentsAfter[parentPkg(l.packageName)]) }
    dao.upsertApps(parents + links + withAutoWatch(deviceOsEntry(existing[DEVICE_OS_PKG])))
  }

  /** A link row copies its app's name, version and watched state. */
  private fun mirrorParent(link: AppEntry, parent: AppEntry?): AppEntry {
    if (parent == null) return link.copy(installed = false, watched = false)
    val versionChanged = link.versionName != parent.versionName
    return link.copy(label = parent.label, versionName = parent.versionName, category = parent.category, isSystem = parent.isSystem,
      installed = parent.installed, watched = parent.watched,
      // OSV answers "affected?" at sync time, so a new app version needs a re-check.
      lastSynced = if (versionChanged && link.source() == ProductSource.OSV) 0 else link.lastSynced)
  }

  /** Link an app to another data source (NVD product, OSV package or Microsoft product). Starts monitoring it. */
  suspend fun addLink(parent: String, vendor: String, product: String) {
    val p = dao.app(parent) ?: return
    if (p.cpeKey() == null && productSource(vendor, product) == ProductSource.NVD) {
      // First NVD product becomes the app's main link.
      dao.setMapping(parent, vendor.trim().lowercase(), product.trim().lowercase(), "manual")
    } else {
      dao.upsertApps(listOf(AppEntry(linkPkg(parent, vendor, product), p.label, p.versionName, p.category, p.isSystem, p.installed,
        watched = true, cpeVendor = vendor, cpeProduct = product, mappingSource = "manual")))
    }
    dao.setWatched(parent, true)
    dao.setLinksWatched(parent, true)
  }

  suspend fun removeLink(linkPackage: String) = dao.deleteApp(linkPackage)

  /** Remove the app's main (NVD) link; its extra links stay. */
  suspend fun clearMainLink(parent: String) = dao.setMapping(parent, null, null, null)

  /** "Android 14 (this phone)": checked against Android Security Bulletins using the phone's security patch level. */
  private fun deviceOsEntry(old: AppEntry?): AppEntry {
    val release = if (android.os.Build.VERSION.SDK_INT == 32) "12L" else android.os.Build.VERSION.RELEASE.substringBefore('.')
    val spl = android.os.Build.VERSION.SECURITY_PATCH.orEmpty()
    val label = "Android $release (this phone)"
    val product = "os:$release"
    if (old == null) {
      return AppEntry(DEVICE_OS_PKG, label, spl, "Operating system", isSystem = false, installed = true,
        cpeVendor = "osv:Android", cpeProduct = product, mappingSource = "builtin")
    }
    // OS upgrade or new security patch → re-check everything.
    val changed = old.cpeProduct != product || old.versionName != spl
    return old.copy(label = label, versionName = spl, cpeVendor = "osv:Android", cpeProduct = product, installed = true,
      lastSynced = if (changed) 0 else old.lastSynced)
  }

  /** Automatic monitoring: installed apps linked to any source (NVD, MSRC, OSV), filtered by user/system per Settings. */
  private fun autoWatch(a: AppEntry, linkCount: Int): Boolean {
    val s = settings.current
    return s.autoMonitor && a.installed && (a.cpeKey() != null || linkCount > 0) && (if (a.isSystem) s.autoSystemApps else s.autoUserApps)
  }

  private fun withAutoWatch(a: AppEntry, linkCount: Int = 0): AppEntry = when {
    a.isManualProduct() || a.isLink() -> a
    a.packageName == DEVICE_OS_PKG -> a.copy(watched = a.watchChoice ?: (settings.current.autoMonitor && settings.current.autoAndroidOs))
    else -> a.copy(watched = a.watchChoice ?: autoWatch(a, linkCount))
  }

  /** Re-apply the automatic rule to all apps (after a Settings change); links follow their app. */
  suspend fun applyAutoMonitor() {
    val all = dao.allApps()
    val linkCount = all.filter { it.isLink() }.groupingBy { parentPkg(it.packageName) }.eachCount()
    val parents = all.filterNot { it.isLink() }.map { withAutoWatch(it, linkCount[it.packageName] ?: 0) }.associateBy { it.packageName }
    val changed = all.mapNotNull { a ->
      val next = if (a.isLink()) a.copy(watched = parents[parentPkg(a.packageName)]?.watched ?: false) else parents[a.packageName]!!
      next.takeIf { it.watched != a.watched }
    }
    if (changed.isNotEmpty()) dao.upsertApps(changed)
  }

  suspend fun clearWatchChoices() { dao.clearWatchChoices(); applyAutoMonitor() }

  /** True if some monitored product has never been synced (so a sync should run now). */
  suspend fun needsSync(): Boolean = dao.watchedApps().any { it.cpeKey() != null && it.lastSynced == 0L }

  suspend fun setWatched(pkg: String, watched: Boolean) { dao.setWatched(pkg, watched); dao.setLinksWatched(pkg, watched) }
  suspend fun setWatched(pkgs: List<String>, watched: Boolean) { dao.setWatched(pkgs, watched); pkgs.forEach { dao.setLinksWatched(it, watched) } }
  suspend fun setMapping(pkg: String, vendor: String?, product: String?) =
    dao.setMapping(pkg, vendor?.trim()?.lowercase()?.ifBlank { null }, product?.trim()?.lowercase()?.ifBlank { null }, if (vendor.isNullOrBlank()) null else "manual")

  /** Track a product that is not an installed app (e.g. something you use on another device). */
  suspend fun addManualProduct(vendor: String, product: String, label: String, version: String?) {
    val v = vendor.trim().lowercase(); val p = product.trim().lowercase()
    dao.upsertApps(listOf(AppEntry("$MANUAL_PREFIX$v:$p", label.ifBlank { "$v $p" }, version?.ifBlank { null }, "Manual", isSystem = false,
      installed = true, watched = true, cpeVendor = v, cpeProduct = p, mappingSource = "manual")))
  }

  /** Track an OSV package or Microsoft product. Keeps the name's case (Maven, Go and MSRC names are case-sensitive). */
  suspend fun addSourceProduct(cpeVendor: String, cpeProduct: String, label: String, version: String?) {
    dao.upsertApps(listOf(AppEntry("$MANUAL_PREFIX$cpeVendor:$cpeProduct", label, version?.trim()?.ifBlank { null },
      if (cpeVendor == "msrc") "Microsoft" else "Open source", isSystem = false, installed = true, watched = true,
      cpeVendor = cpeVendor, cpeProduct = cpeProduct, mappingSource = "manual")))
  }

  suspend fun deleteApp(pkg: String) = dao.deleteApp(pkg)

  /** OSV answers "is this version affected" at sync time, so a version change needs a re-sync. */
  suspend fun setVersion(pkg: String, version: String?) {
    val v = version?.trim()?.ifBlank { null }
    dao.setVersion(pkg, v)
    val app = dao.app(pkg)
    if (app?.source() == ProductSource.OSV) dao.resetSynced(pkg)
    // Links follow their app's version.
    dao.allApps().filter { it.isLink() && parentPkg(it.packageName) == pkg }.forEach { l ->
      dao.setVersion(l.packageName, v)
      if (l.source() == ProductSource.OSV) dao.resetSynced(l.packageName)
    }
  }

  // ---- OSV.dev and Microsoft catalog helpers
  /** (all known vulnerabilities, how many affect [version] or null). */
  suspend fun checkOsvPackage(ecosystem: String, name: String, version: String?): Pair<Int, Int?> {
    val all = OsvClient.query(ecosystem, name).map { OsvClient.primaryId(it) }.toSet().size
    val affecting = version?.takeIf { it.isNotBlank() }?.let { v -> OsvClient.query(ecosystem, name, v).map { OsvClient.primaryId(it) }.toSet().size }
    return all to affecting
  }

  suspend fun searchMicrosoftProducts(text: String): List<MsrcProduct> = MsrcClient.searchProducts(text)

  suspend fun osvFixedVersions(cveId: String): List<String> = OsvClient.fixedVersionsFor(cveId)

  // ---- product catalog (everything NVD publishes, not just installed apps)
  suspend fun searchCatalog(keyword: String, start: Int, vendor: String?): CpePage =
    NvdClient.searchProductsPage(keyword, settings.current.effectiveNvdKey, start, vendor)

  suspend fun kevProducts(): List<KevProduct> = KevClient.products(kevEntries())

  /** Finds the NVD vendor:product for a CISA KEV product by looking at its CVEs. */
  suspend fun resolveKev(p: KevProduct): CpeSuggestion? {
    fun norm(s: String) = s.lowercase().replace(Regex("[^a-z0-9]"), "")
    val v = norm(p.vendor)
    val words = p.product.lowercase().split(Regex("[^a-z0-9]+")).filter { it.length > 1 }
    for (cve in p.cveIds.take(3)) {
      val candidates = NvdClient.productsForCve(cve, settings.current.effectiveNvdKey)
      val best = candidates.map { (cv, cp) ->
        val vendorScore = if (norm(cv) == v) 10 else if (norm(cv).contains(v) || v.contains(norm(cv))) 6 else 0
        val productScore = words.count { cp.contains(it) } * 3 + if (norm(cp) == norm(p.product)) 5 else 0
        Triple(cv, cp, vendorScore + productScore) to vendorScore
      }.filter { it.second > 0 }.maxByOrNull { it.first.third }?.first
      if (best != null) return CpeSuggestion(best.first, best.second, "${p.vendor} ${p.product}")
      delay(700)
    }
    return null
  }

  suspend fun addProducts(items: List<CpeSuggestion>) = items.forEach { addManualProduct(it.vendor, it.product, it.title, null) }

  suspend fun searchProducts(keyword: String): List<CpeSuggestion> = NvdClient.searchProducts(keyword, settings.current.effectiveNvdKey)

  /**
   * Pull CVEs for every watched product from its database (NVD, OSV.dev, Android bulletins, Microsoft MSRC),
   * then enrich everything with CISA KEV and FIRST EPSS. One failing source doesn't stop the others.
   * Returns warnings (empty = all good).
   */
  suspend fun sync(progress: suspend (String) -> Unit): List<String> {
    val now = Instant.now()
    val products = dao.watchedApps().filter { it.cpeKey() != null }.groupBy { it.cpeKey()!! }
    val warnings = mutableListOf<String>()
    var index = 0
    for ((cpeKey, apps) in products) {
      index++
      val app = apps.first()
      val tag = "$index/${products.size}"
      try {
        when (app.source()) {
          ProductSource.NVD -> syncNvd(cpeKey, apps, tag, now, progress)
          ProductSource.OSV -> syncOsv(cpeKey, apps, tag, now, progress)
          ProductSource.ANDROID_OS -> syncAndroidOs(cpeKey, apps, tag, now, progress)
          ProductSource.MSRC -> syncMsrc(cpeKey, apps, tag, now, progress)
        }
      } catch (e: kotlinx.coroutines.CancellationException) {
        throw e
      } catch (e: Exception) {
        warnings += "${productKeyLabel(app.cpeVendor, app.cpeProduct)}: ${e.message ?: e.javaClass.simpleName}"
      }
    }

    try {
      // CVEs that were only opened from "Search all CVEs" (not linked to anything you track) are dropped,
      // so the database and the daily EPSS refresh don't keep growing. Searching again re-fetches them.
      dao.deleteUntrackedCves()
      progress("Downloading CISA KEV catalog…")
      val kev = KevClient.fetch().also { kevEntriesCache = it; kevFetchedAt = System.currentTimeMillis() }
      val known = dao.allCveIds().toHashSet()
      db.withTransaction {
        dao.clearKev()
        kev.filter { it.cveId in known }.forEach { dao.setKev(it.cveId, it.dateAdded, it.dueDate, it.action, it.ransomware, it.name) }
      }
      // EPSS updates once a day: refresh every score daily, otherwise only CVEs that don't have one yet.
      val dailyDue = System.currentTimeMillis() - settings.current.lastEpssRefresh > Duration.ofHours(20).toMillis()
      val cveIds = (if (dailyDue) known else dao.idsWithoutEpss().toSet()).filter { it.startsWith("CVE-") }
      if (cveIds.isNotEmpty()) {
        progress("Fetching EPSS scores for ${cveIds.size} CVEs…")
        val epss = EpssClient.fetch(cveIds)
        db.withTransaction { epss.forEach { (id, v) -> dao.setEpss(id, v.first, v.second) } }
      }
      if (dailyDue) settings.update { it.copy(lastEpssRefresh = System.currentTimeMillis()) }
    } catch (e: kotlinx.coroutines.CancellationException) {
      throw e
    } catch (e: Exception) {
      warnings += "KEV/EPSS: ${e.message}"
    }
    return warnings
  }

  private suspend fun syncNvd(cpeKey: String, apps: List<AppEntry>, tag: String, now: Instant, progress: suspend (String) -> Unit) {
    val vendor = apps.first().cpeVendor!!
    val product = apps.first().cpeProduct!!
    val lastSynced = apps.minOf { it.lastSynced }
    val incremental = lastSynced > 0 && Duration.between(Instant.ofEpochMilli(lastSynced), now).toDays() < 110
    val since = if (incremental) Instant.ofEpochMilli(lastSynced).minus(Duration.ofDays(1)) else null
    progress("NVD $tag: $vendor:$product")
    val fetched = NvdClient.fetchCves(vendor, product, settings.current.effectiveNvdKey, since) { done, total -> progress("NVD $tag: $vendor:$product ($done/$total)") }

    val existingLinks = dao.linksFor(cpeKey).associateBy { it.cveId }
    val existingCves = fetched.map { it.entry.id }.chunked(500).flatMap { dao.cves(it) }.associateBy { it.id }
    val cves = fetched.map { f -> mergeExisting(f.entry, existingCves[f.entry.id]) }
    val links = fetched.map { f ->
      val rangesJson = AppJson.encodeToString(ListSerializer(CpeRange.serializer()), f.ranges)
      val old = existingLinks[f.entry.id]
      // On the very first import of a product, don't treat its whole history as "new" alerts.
      old?.copy(rangesJson = rangesJson) ?: ProductCve(cpeKey, f.entry.id, rangesJson, now.toEpochMilli(), alerted = lastSynced == 0L)
    }
    db.withTransaction {
      cves.chunked(500).forEach { dao.upsertCves(it) }
      links.chunked(500).forEach { dao.upsertLinks(it) }
      dao.setSynced(vendor, product, now.toEpochMilli())
    }
  }

  /** Stores CVEs from OSV/MSRC with their fix info, merging with records other databases already provided. */
  private suspend fun saveForeign(cpeKey: String, apps: List<AppEntry>, now: Instant, entries: Map<String, Pair<CveEntry, FixInfo>>) {
    val lastSynced = apps.minOf { it.lastSynced }
    val existingLinks = dao.linksFor(cpeKey).associateBy { it.cveId }
    val existingCves = entries.keys.chunked(500).flatMap { dao.cves(it) }.associateBy { it.id }
    val cves = entries.values.map { (e, _) -> mergeForeign(e, existingCves[e.id]) }
    val links = entries.map { (id, pair) ->
      val fixJson = AppJson.encodeToString(FixInfo.serializer(), pair.second)
      existingLinks[id]?.copy(fixJson = fixJson) ?: ProductCve(cpeKey, id, "[]", now.toEpochMilli(), alerted = lastSynced == 0L, fixJson = fixJson)
    }
    db.withTransaction {
      cves.chunked(500).forEach { dao.upsertCves(it) }
      links.chunked(500).forEach { dao.upsertLinks(it) }
      apps.forEach { dao.setSynced(it.cpeVendor!!, it.cpeProduct!!, now.toEpochMilli()) }
    }
  }

  /** OSV.dev package: all known vulnerabilities, with OSV's own "affects this version" answer. */
  private suspend fun syncOsv(cpeKey: String, apps: List<AppEntry>, tag: String, now: Instant, progress: suspend (String) -> Unit) {
    val app = apps.first()
    val eco = app.cpeVendor!!.removePrefix("osv:")
    val name = app.cpeProduct!!
    val version = app.versionName?.takeIf { it.isNotBlank() }
    progress("OSV $tag: $eco $name")
    val all = OsvClient.query(eco, name)
    val affecting = version?.let { v -> OsvClient.query(eco, name, v).map { OsvClient.primaryId(it) }.toSet() }
    val out = LinkedHashMap<String, Pair<CveEntry, FixInfo>>()
    for (v in all) {
      val entry = OsvClient.toEntry(v) ?: continue
      val fixed = OsvClient.fixedVersions(v, eco, name)
      val aff = when { affecting == null -> "UNKNOWN"; entry.id in affecting -> "YES"; else -> "NO" }
      val prev = out[entry.id]
      // Several OSV records (GHSA, PYSEC…) can describe the same CVE: merge them.
      out[entry.id] = if (prev == null) entry to FixInfo("OSV", aff, fixed, note = v["id"]?.toString()?.trim('"'))
      else prev.first to prev.second.copy(affected = if (prev.second.affected == "YES" || aff == "YES") "YES" else aff, fixedIn = (prev.second.fixedIn + fixed).distinct())
    }
    saveForeign(cpeKey, apps, now, out)
  }

  /** This phone's Android OS: Android Security Bulletin entries (via OSV) checked against the security patch level. */
  private suspend fun syncAndroidOs(cpeKey: String, apps: List<AppEntry>, tag: String, now: Instant, progress: suspend (String) -> Unit) {
    val app = apps.first()
    val release = app.cpeProduct!!.removePrefix("os:")
    val spl = app.versionName.orEmpty()
    val out = LinkedHashMap<String, Pair<CveEntry, FixInfo>>()
    OsvClient.androidComponents.forEachIndexed { i, component ->
      progress("Android bulletins $tag: ${component.substringAfterLast('/')} (${i + 1}/${OsvClient.androidComponents.size})")
      for (v in OsvClient.query("Android", component, release)) {
        val entry = OsvClient.toEntry(v) ?: continue
        val fixSpl = OsvClient.androidFixSpl(v, component, release)
        val aff = when { fixSpl == null || spl.isBlank() -> "UNKNOWN"; spl >= fixSpl -> "NO"; else -> "YES" }
        val prev = out[entry.id]
        if (prev == null || (aff == "YES" && prev.second.affected != "YES")) {
          out[entry.id] = entry to FixInfo("Android", aff, listOfNotNull(fixSpl?.let { "Security patch $it" }), note = component)
        }
      }
    }
    saveForeign(cpeKey, apps, now, out)
  }

  /** Microsoft product: CVEs from the Security Update Guide with the KB and fixed build. */
  private suspend fun syncMsrc(cpeKey: String, apps: List<AppEntry>, tag: String, now: Instant, progress: suspend (String) -> Unit) {
    val product = apps.first().cpeProduct!!
    val lastSynced = apps.minOf { it.lastSynced }
    val since = if (lastSynced > 0) Instant.ofEpochMilli(lastSynced).minus(Duration.ofDays(2))
      else now.minus(Duration.ofDays(30L * settings.current.msrcMonths))
    progress("Microsoft $tag: $product")
    val rows = MsrcClient.productRows(product, since).groupBy { it.cve }.mapValues { (_, r) -> r.maxBy { it.releaseDate } }
    if (rows.isEmpty()) { saveForeign(cpeKey, apps, now, emptyMap()); return }
    val info = MsrcClient.details(rows.keys.toList()) { done -> progress("Microsoft $tag: $product (details ${minOf(done, rows.size)}/${rows.size})") }
    val out = rows.mapValues { (cve, row) ->
      MsrcClient.toEntry(row, info[cve]) to FixInfo("MSRC", affected = null, kb = row.kb, kbUrl = row.kbUrl, fixedBuild = row.fixedBuild, note = row.impact)
    }
    saveForeign(cpeKey, apps, now, out)
  }

  private fun unionCsv(a: String, b: String) = (a.split(',') + b.split(',')).map { it.trim() }.filter { it.isNotEmpty() }.distinct().joinToString(",")

  /** A record from NVD: keep enrichment (KEV, EPSS, update marks, other sources) from what we stored. */
  private fun mergeExisting(new: CveEntry, old: CveEntry?): CveEntry {
    if (old == null) return new.copy(sources = unionCsv(new.sources, "NVD"))
    val withKev = if (new.kev) new.copy(kevRansomware = old.kevRansomware) else new.copy(kev = old.kev, kevDateAdded = old.kevDateAdded,
      kevDueDate = old.kevDueDate, kevAction = old.kevAction, kevRansomware = old.kevRansomware, kevName = old.kevName)
    val merged = withKev.copy(epss = old.epss, epssPercentile = old.epssPercentile,
      updatedAt = old.updatedAt, updateNote = old.updateNote, updateSeen = old.updateSeen,
      sources = unionCsv(unionCsv(old.sources, new.sources), "NVD"), msExploited = old.msExploited || new.msExploited,
      affectedProducts = unionCsv(new.affectedProducts, old.affectedProducts.split(',').filter { it.startsWith("osv:") || it.startsWith("msrc:") }.joinToString(",")))
    // NVD changed this record since we last stored it → mark it "Updated" (green) with what changed.
    if ("NVD" in old.sourceList() && old.lastModified.isNotBlank() && new.lastModified.isNotBlank() && new.lastModified != old.lastModified) {
      return merged.copy(updatedAt = System.currentTimeMillis(), updateNote = describeChange(old, merged), updateSeen = false)
    }
    return merged
  }

  /** A record from OSV or MSRC. NVD's data wins when we have it; otherwise take the new record and keep enrichment. */
  private fun mergeForeign(new: CveEntry, old: CveEntry?): CveEntry {
    if (old == null) return new
    val sources = unionCsv(old.sources, new.sources)
    val products = unionCsv(old.affectedProducts, new.affectedProducts)
    if ("NVD" in old.sourceList()) {
      return old.copy(sources = sources, affectedProducts = products, msExploited = old.msExploited || new.msExploited,
        cwes = old.cwes.ifBlank { new.cwes })
    }
    val merged = new.copy(
      kev = old.kev, kevDateAdded = old.kevDateAdded, kevDueDate = old.kevDueDate, kevAction = old.kevAction, kevRansomware = old.kevRansomware, kevName = old.kevName,
      epss = old.epss, epssPercentile = old.epssPercentile, updatedAt = old.updatedAt, updateNote = old.updateNote, updateSeen = old.updateSeen,
      sources = sources, affectedProducts = products, msExploited = old.msExploited || new.msExploited,
      cvssScore = new.cvssScore ?: old.cvssScore, severity = if (new.cvssScore == null && new.severity == "NONE") old.severity else new.severity,
    )
    val sameSource = new.sourceList().any { it in old.sourceList() }
    if (sameSource && old.lastModified.isNotBlank() && new.lastModified.isNotBlank() && new.lastModified != old.lastModified) {
      return merged.copy(updatedAt = System.currentTimeMillis(), updateNote = describeChange(old, merged), updateSeen = false)
    }
    return merged
  }

  private fun describeChange(old: CveEntry, new: CveEntry): String {
    val parts = mutableListOf<String>()
    if (old.severity != new.severity || old.cvssScore != new.cvssScore) {
      fun s(c: CveEntry) = Severity.label(c.severity) + (c.cvssScore?.let { " $it" } ?: "")
      parts += "Severity ${s(old)} → ${s(new)}"
    }
    if (!old.kev && new.kev) parts += "Added to CISA KEV (actively exploited)"
    if (old.status != new.status && new.status.isNotBlank()) parts += "Status ${old.status.ifBlank { "–" }} → ${new.status}"
    if (old.description != new.description) parts += "Description changed"
    if (old.affectedProducts.isNotBlank() && old.affectedProducts != new.affectedProducts) parts += "Affected products changed"
    if (old.referencesJson != new.referencesJson) parts += "References updated"
    if (old.cwes != new.cwes) parts += "Weakness (CWE) changed"
    return parts.joinToString(" · ").ifBlank { "Record updated by ${new.sourceList().firstOrNull() ?: "NVD"}" }
  }

  suspend fun markUpdateSeen(id: String) = dao.markUpdateSeen(id)

  // CISA KEV catalog for the catalog tab and search; refreshed after 6 hours so a long-running app doesn't go stale.
  private var kevEntriesCache: List<com.vulft.app.data.remote.KevEntry>? = null
  private var kevFetchedAt = 0L
  private suspend fun kevEntries(): List<com.vulft.app.data.remote.KevEntry> {
    val cached = kevEntriesCache
    if (cached != null && System.currentTimeMillis() - kevFetchedAt < Duration.ofHours(6).toMillis()) return cached
    return KevClient.fetch().also { kevEntriesCache = it; kevFetchedAt = System.currentTimeMillis() }
  }

  /**
   * Search CVEs across the databases that can be searched:
   * - a CVE ID is looked up in NVD, Microsoft MSRC, OSV.dev and CISA KEV and merged into one record;
   * - words search NVD, Microsoft titles and the CISA KEV catalog.
   * (OSV has no text search – it's searched by CVE ID here and by package in the catalog.)
   * Results are stored locally so the detail screen can open them; EPSS is added.
   */
  suspend fun searchAllCves(q: CveQuery, before: Int?): CvePage {
    val idMatch = Regex("""(?i)^\s*(CVE-\d{4}-\d{4,})\s*$""").find(q.text)?.groupValues?.get(1)?.uppercase()
    val key = settings.current.effectiveNvdKey
    val found = LinkedHashMap<String, CveEntry>()
    var olderStart: Int? = null
    var total = 0
    var nvdError: Throwable? = null

    // NVD (pages, newest first)
    runCatching { NvdClient.searchCves(q, key, before) }
      .onSuccess { p -> olderStart = p.olderStart; total = p.total; p.items.forEach { found[it.id] = it } }
      .onFailure { nvdError = it }

    if (before == null) {
      val text = q.text.trim()
      // Microsoft (titles, or the exact CVE)
      if (idMatch != null || text.isNotBlank()) {
        runCatching { MsrcClient.searchVulnerabilities(text = text.takeIf { idMatch == null }, cveId = idMatch) }.getOrDefault(emptyList())
          .forEach { e -> found[e.id] = found[e.id]?.let { mergeForeign(e, it) } ?: e }
      }
      // OSV (exact CVE only)
      if (idMatch != null) {
        runCatching { OsvClient.toEntry(OsvClient.vuln(idMatch)) }.getOrNull()?.let { e -> found[e.id] = found[e.id]?.let { mergeForeign(e, it) } ?: e }
      }
      // CISA KEV catalog (exact CVE, or words in name/vendor/product/description)
      val kev = runCatching { kevEntries() }.getOrDefault(emptyList())
      val kevMatches = when {
        idMatch != null -> kev.filter { it.cveId == idMatch }
        text.isNotBlank() -> text.lowercase().split(Regex("\\s+")).let { words ->
          kev.filter { k ->
            val hay = "${k.cveId} ${k.name} ${k.vendorProject} ${k.product} ${k.shortDescription}".lowercase()
            words.all { it in hay }
          }.take(100)
        }
        else -> emptyList()
      }
      kevMatches.forEach { k ->
        val cur = found[k.cveId]
        found[k.cveId] = cur?.copy(kev = true, kevDateAdded = k.dateAdded, kevDueDate = k.dueDate, kevAction = k.action, kevRansomware = k.ransomware, kevName = k.name)
          ?: k.toEntry()
      }
      // Microsoft/KEV results don't go through NVD's server-side filters, so apply them here.
      val cutoff = q.lastDays?.let { java.time.LocalDate.now().minusDays(it.toLong()).toString() }
      found.entries.removeAll { (_, e) ->
        "NVD" !in e.sourceList() &&
          ((q.severity != null && e.severity != q.severity) || (q.kevOnly && !e.exploited) || (cutoff != null && e.published.take(10) < cutoff))
      }
    }

    if (found.isEmpty()) {
      nvdError?.let { if (idMatch == null) throw it }
      return CvePage(emptyList(), olderStart, total)
    }

    val ids = found.keys.toList()
    val epss = runCatching { EpssClient.fetch(ids.filter { it.startsWith("CVE-") }) }.getOrDefault(emptyMap())
    val existing = ids.chunked(500).flatMap { dao.cves(it) }.associateBy { it.id }
    val merged = found.values.map { e ->
      val m = if ("NVD" in e.sourceList()) mergeExisting(e, existing[e.id]) else mergeForeign(e, existing[e.id])
      epss[e.id]?.let { m.copy(epss = it.first, epssPercentile = it.second) } ?: m
    }.sortedByDescending { it.published }
    dao.upsertCves(merged)
    return CvePage(merged, olderStart, maxOf(total, merged.size))
  }

  suspend fun unalertedLinks() = dao.unalertedLinks()
  suspend fun markAlerted(cpeKey: String, cveId: String) = dao.markAlerted(cpeKey, cveId)
}
