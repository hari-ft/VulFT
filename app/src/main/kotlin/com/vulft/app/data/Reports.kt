package com.vulft.app.data

import java.util.Date
import java.util.Properties
import javax.mail.Authenticator
import javax.mail.Message
import javax.mail.PasswordAuthentication
import javax.mail.Session
import javax.mail.Transport
import javax.mail.internet.InternetAddress
import javax.mail.internet.MimeMessage
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray

object Mailer {
  suspend fun send(cfg: SmtpConfig, subject: String, html: String) = withContext(Dispatchers.IO) {
    require(cfg.host.isNotBlank()) { "SMTP host is not set" }
    val to = cfg.recipientList()
    require(to.isNotEmpty()) { "No recipients set" }
    val auth = cfg.username.isNotBlank()
    val props = Properties().apply {
      put("mail.smtp.host", cfg.host.trim())
      put("mail.smtp.port", cfg.port.toString())
      put("mail.smtp.auth", auth.toString())
      put("mail.smtp.connectiontimeout", "20000")
      put("mail.smtp.timeout", "20000")
      put("mail.smtp.writetimeout", "20000")
      when (cfg.security) {
        "STARTTLS" -> { put("mail.smtp.starttls.enable", "true"); put("mail.smtp.starttls.required", "true") }
        "SSL" -> { put("mail.smtp.ssl.enable", "true") }
      }
    }
    val session = if (auth) {
      Session.getInstance(props, object : Authenticator() {
        override fun getPasswordAuthentication() = PasswordAuthentication(cfg.username, cfg.password)
      })
    } else Session.getInstance(props)
    val msg = MimeMessage(session).apply {
      setFrom(InternetAddress(cfg.from.ifBlank { cfg.username }))
      setRecipients(Message.RecipientType.TO, InternetAddress.parse(to.joinToString(",")))
      setSubject(subject, "UTF-8")
      setContent(html, "text/html; charset=utf-8")
      sentDate = Date()
    }
    Transport.send(msg)
  }
}

object Reports {
  private fun esc(s: String) = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
  private fun pct(d: Double?) = d?.let { String.format(java.util.Locale.US, "%.1f%%", it * 100) } ?: ""

  private fun sevColor(s: String) = when (s) { "CRITICAL" -> "#b3261e"; "HIGH" -> "#e8590c"; "MEDIUM" -> "#c99a06"; "LOW" -> "#2f7d32"; else -> "#666" }

  fun emailHtml(title: String, items: List<VulnItem>): String = buildString {
    append("<html><body style='font-family:sans-serif'>")
    append("<h2>${esc(title)}</h2><p>${items.size} vulnerabilities</p>")
    append("<table border='1' cellspacing='0' cellpadding='6' style='border-collapse:collapse;font-size:13px'>")
    append("<tr style='background:#eee'><th>CVE</th><th>App</th><th>Severity</th><th>Exploited</th><th>EPSS</th><th>Your version</th><th>Fix</th><th>Published</th><th>Description</th></tr>")
    items.forEach { i ->
      val c = i.cve
      append("<tr>")
      append("<td><a href='https://nvd.nist.gov/vuln/detail/${c.id}'>${c.id}</a></td>")
      append("<td>${esc(i.row.appLabel)}<br><small>${esc(i.row.appVersion ?: "")}</small></td>")
      append("<td style='color:${sevColor(c.severity)};font-weight:bold'>${Severity.label(c.severity)} ${c.cvssScore ?: ""}</td>")
      append("<td>${if (c.exploited) "<b style='color:#b3261e'>YES</b>" + (if (c.kev) " (CISA)" else " (Microsoft)") else "no"}</td>")
      append("<td>${pct(c.epss)}</td>")
      append("<td>${esc(i.affected.label)}</td>")
      append("<td>${esc(i.fixSummary() ?: "")}</td>")
      append("<td>${c.published.take(10)}</td>")
      append("<td>${esc(c.description.take(400))}</td>")
      append("</tr>")
    }
    append("</table><p style='color:#888;font-size:11px'>Sent by VulFT. Data: NVD, CISA KEV, FIRST EPSS.</p></body></html>")
  }

  private fun csvCell(s: String?): String {
    val v = s ?: ""
    return if (v.any { it == ',' || it == '"' || it == '\n' || it == '\r' }) "\"" + v.replace("\"", "\"\"") + "\"" else v
  }

  fun csv(items: List<VulnItem>): String = buildString {
    appendLine("cve_id,app,package,installed_version,category,severity,cvss_score,cvss_version,cvss_vector,kev,kev_date_added,ms_exploited,epss,epss_percentile,version_check,affected_ranges,fix,sources,published,last_modified,cwes,description,url")
    items.forEach { i ->
      val c = i.cve
      appendLine(listOf(c.id, i.row.appLabel, i.row.pkg, i.row.appVersion, i.row.appCategory, c.severity, c.cvssScore?.toString(), c.cvssVersion, c.cvssVector,
        c.kev.toString(), c.kevDateAdded, c.msExploited.toString(), c.epss?.toString(), c.epssPercentile?.toString(), i.affected.name, i.rangeList.joinToString("; ") { it.describe() },
        i.fixSummary(), c.sources,
        c.published, c.lastModified, c.cwes, c.description, "https://nvd.nist.gov/vuln/detail/${c.id}").joinToString(",") { csvCell(it) })
    }
  }

  fun json(items: List<VulnItem>): String {
    val arr = JsonArray(items.map { i ->
      val c = i.cve
      buildJsonObject {
        put("cveId", c.id); put("app", i.row.appLabel); put("package", i.row.pkg); put("installedVersion", i.row.appVersion)
        put("category", i.row.appCategory); put("severity", c.severity); put("cvssScore", c.cvssScore); put("cvssVersion", c.cvssVersion)
        put("cvssVector", c.cvssVector); put("kev", c.kev); put("kevDateAdded", c.kevDateAdded); put("msExploited", c.msExploited); put("epss", c.epss)
        put("fix", i.fixSummary()); put("sources", c.sources)
        put("epssPercentile", c.epssPercentile); put("versionCheck", i.affected.name)
        putJsonArray("affectedRanges") { i.rangeList.forEach { add(JsonPrimitive(it.describe())) } }
        put("published", c.published); put("lastModified", c.lastModified); put("cwes", c.cwes); put("description", c.description)
        put("url", "https://nvd.nist.gov/vuln/detail/${c.id}")
      }
    })
    return AppJson.encodeToString(JsonArray.serializer(), arr)
  }
}
