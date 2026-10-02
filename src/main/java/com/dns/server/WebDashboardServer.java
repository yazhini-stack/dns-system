package com.dns.server;

import com.dns.cache.DnsCache;
import com.dns.protocol.DnsMessage;
import com.dns.protocol.DnsRecord;
import com.dns.protocol.RecordType;
import com.dns.stats.QueryLogger;
import com.dns.stats.QueryStats;
import com.dns.util.Logger;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Built-in HTTP Web Dashboard server running on port 5380 using standard JDK HttpServer.
 * Provides a responsive, real-time web interface alongside the Swing GUI.
 */
public class WebDashboardServer {

    private final DnsServer dnsServer;
    private final int httpPort;
    private HttpServer httpServer;

    public WebDashboardServer(DnsServer dnsServer, int httpPort) {
        this.dnsServer = dnsServer;
        this.httpPort = httpPort;
    }

    public synchronized void start() throws IOException {
        httpServer = HttpServer.create(new InetSocketAddress(httpPort), 0);

        httpServer.createContext("/", this::handleIndex);
        httpServer.createContext("/api/stats", this::handleStats);
        httpServer.createContext("/api/logs", this::handleLogs);
        httpServer.createContext("/api/flush", this::handleFlush);
        httpServer.createContext("/api/records", this::handleAddRecord);
        httpServer.createContext("/api/query", this::handleTestQuery);

        httpServer.setExecutor(null); // default executor
        httpServer.start();
        Logger.info("Web Dashboard accessible at: http://localhost:" + httpPort);
    }

    public synchronized void stop() {
        if (httpServer != null) {
            httpServer.stop(1);
            Logger.info("Web Dashboard stopped.");
        }
    }

    private void handleIndex(HttpExchange exchange) throws IOException {
        if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendResponse(exchange, 405, "text/plain", "Method Not Allowed");
            return;
        }

        String html = getDashboardHtml();
        sendResponse(exchange, 200, "text/html; charset=UTF-8", html);
    }

    private void handleStats(HttpExchange exchange) throws IOException {
        QueryStats stats = dnsServer.getStats();
        StringBuilder json = new StringBuilder("{");
        json.append("\"totalQueries\":").append(stats.getTotalQueries()).append(",");
        json.append("\"cacheHits\":").append(stats.getCacheHits()).append(",");
        json.append("\"cacheMisses\":").append(stats.getCacheMisses()).append(",");
        json.append("\"blockedQueries\":").append(stats.getBlockedQueries()).append(",");
        json.append("\"authoritativeQueries\":").append(stats.getAuthoritativeQueries()).append(",");
        json.append("\"upstreamQueries\":").append(stats.getUpstreamQueries()).append(",");
        json.append("\"qpm\":").append(stats.getQueriesPerMinute()).append(",");
        json.append("\"cacheHitRatio\":").append(String.format("%.2f", stats.getCacheHitRatio() * 100)).append(",");
        json.append("\"dnsPort\":").append(dnsServer.getBoundPort()).append(",");
        json.append("\"zone\":").append("\"").append(dnsServer.getZoneStore().getOrigin()).append("\",");

        // Top Queried
        json.append("\"topQueried\":[");
        List<QueryStats.DomainCount> topQ = stats.getTopQueried(5);
        for (int i = 0; i < topQ.size(); i++) {
            if (i > 0) json.append(",");
            json.append("{\"domain\":\"").append(topQ.get(i).getDomain()).append("\",\"count\":").append(topQ.get(i).getCount()).append("}");
        }
        json.append("],");

        // Top Blocked
        json.append("\"topBlocked\":[");
        List<QueryStats.DomainCount> topB = stats.getTopBlocked(5);
        for (int i = 0; i < topB.size(); i++) {
            if (i > 0) json.append(",");
            json.append("{\"domain\":\"").append(topB.get(i).getDomain()).append("\",\"count\":").append(topB.get(i).getCount()).append("}");
        }
        json.append("]}");

        sendResponse(exchange, 200, "application/json", json.toString());
    }

    private void handleLogs(HttpExchange exchange) throws IOException {
        List<QueryLogger.LogEntry> entries = dnsServer.getQueryLogger().getRecentEntries();
        StringBuilder json = new StringBuilder("[");
        for (int i = 0; i < entries.size(); i++) {
            QueryLogger.LogEntry e = entries.get(i);
            if (i > 0) json.append(",");
            json.append("{")
                .append("\"time\":\"").append(e.getFormattedTime()).append("\",")
                .append("\"client\":\"").append(e.getClientIp()).append("\",")
                .append("\"domain\":\"").append(e.getDomain()).append("\",")
                .append("\"type\":\"").append(e.getRecordType().getName()).append("\",")
                .append("\"rcode\":\"").append(e.getRcode()).append("\",")
                .append("\"source\":\"").append(e.getSource()).append("\",")
                .append("\"latency\":").append(e.getLatencyMs())
                .append("}");
        }
        json.append("]");
        sendResponse(exchange, 200, "application/json", json.toString());
    }

    private void handleFlush(HttpExchange exchange) throws IOException {
        if ("POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            dnsServer.getCache().flush();
            sendResponse(exchange, 200, "application/json", "{\"status\":\"ok\",\"message\":\"Cache flushed\"}");
        } else {
            sendResponse(exchange, 405, "text/plain", "Method Not Allowed");
        }
    }

    private void handleAddRecord(HttpExchange exchange) throws IOException {
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendResponse(exchange, 405, "text/plain", "Method Not Allowed");
            return;
        }

        try (InputStream in = exchange.getRequestBody()) {
            String body = new String(in.readAllBytes(), StandardCharsets.UTF_8);
            // Simple key-value form parser (e.g., domain=test&type=A&ttl=3600&val=1.2.3.4)
            String domain = null, typeStr = "A", ttlStr = "3600", val = null;
            for (String pair : body.split("&")) {
                String[] kv = pair.split("=");
                if (kv.length == 2) {
                    String k = java.net.URLDecoder.decode(kv[0], StandardCharsets.UTF_8).trim();
                    String v = java.net.URLDecoder.decode(kv[1], StandardCharsets.UTF_8).trim();
                    if (k.equals("domain")) domain = v;
                    else if (k.equals("type")) typeStr = v;
                    else if (k.equals("ttl")) ttlStr = v;
                    else if (k.equals("val")) val = v;
                }
            }

            if (domain != null && val != null) {
                RecordType type = RecordType.fromName(typeStr);
                long ttl = Long.parseLong(ttlStr);
                DnsRecord record = switch (type) {
                    case A -> DnsRecord.createA(domain, ttl, val);
                    case AAAA -> DnsRecord.createAAAA(domain, ttl, val);
                    case CNAME -> DnsRecord.createCNAME(domain, ttl, val);
                    case TXT -> DnsRecord.createTXT(domain, ttl, val);
                    case MX -> DnsRecord.createMX(domain, ttl, 10, val);
                    default -> null;
                };

                if (record != null) {
                    dnsServer.getZoneStore().addRecord(record);
                    sendResponse(exchange, 200, "application/json", "{\"status\":\"ok\",\"message\":\"Record added\"}");
                    return;
                }
            }
            sendResponse(exchange, 400, "application/json", "{\"status\":\"error\",\"message\":\"Invalid parameters\"}");
        } catch (Exception e) {
            sendResponse(exchange, 500, "application/json", "{\"status\":\"error\",\"message\":\"" + e.getMessage() + "\"}");
        }
    }

    private void handleTestQuery(HttpExchange exchange) throws IOException {
        String queryDomain = "www.mycompany.local";
        String typeStr = "A";

        if (exchange.getRequestURI().getQuery() != null) {
            for (String pair : exchange.getRequestURI().getQuery().split("&")) {
                String[] kv = pair.split("=");
                if (kv.length == 2) {
                    if (kv[0].equals("domain")) queryDomain = kv[1];
                    else if (kv[0].equals("type")) typeStr = kv[1];
                }
            }
        }

        RecordType type = RecordType.fromName(typeStr);
        DnsMessage query = DnsMessage.createQuery(1234, queryDomain, type, true);
        DnsMessage resp = dnsServer.getQueryHandler().handleQuery(query, InetAddress.getByName("127.0.0.1"));

        StringBuilder json = new StringBuilder("{");
        json.append("\"domain\":\"").append(queryDomain).append("\",");
        json.append("\"type\":\"").append(type.getName()).append("\",");
        json.append("\"rcode\":\"").append(com.dns.protocol.DnsHeader.rcodeToString(resp.getHeader().getRcode())).append("\",");
        json.append("\"aa\":").append(resp.getHeader().isAa()).append(",");
        json.append("\"ra\":").append(resp.getHeader().isRa()).append(",");
        json.append("\"answers\":[");
        for (int i = 0; i < resp.getAnswers().size(); i++) {
            DnsRecord r = resp.getAnswers().get(i);
            if (i > 0) json.append(",");
            json.append("{\"name\":\"").append(r.getName()).append("\",\"type\":\"").append(r.getType()).append("\",\"ttl\":").append(r.getTtl()).append(",\"value\":\"").append(r.getParsedValue().replace("\"", "\\\"")).append("\"}");
        }
        json.append("]}");
        sendResponse(exchange, 200, "application/json", json.toString());
    }

    private void sendResponse(HttpExchange exchange, int statusCode, String contentType, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", contentType);
        exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        exchange.sendResponseHeaders(statusCode, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }

    private String getDashboardHtml() {
        return """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>DNS Server & Resolver Dashboard</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-dark: #0f111a;
      --bg-card: #1a1d2d;
      --bg-panel: #22263d;
      --accent-cyan: #00d2ff;
      --accent-green: #26de81;
      --accent-red: #ff4d6d;
      --accent-amber: #fed330;
      --accent-purple: #a55eea;
      --text-main: #f5f6fa;
      --text-muted: #8c92b2;
      --border: rgba(255, 255, 255, 0.08);
    }
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Inter', sans-serif; }
    body { background-color: var(--bg-dark); color: var(--text-main); padding: 24px; min-height: 100vh; }
    .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; padding-bottom: 20px; border-bottom: 1px solid var(--border); }
    .header-title h1 { font-size: 24px; font-weight: 700; color: #fff; letter-spacing: -0.5px; }
    .header-title p { color: var(--accent-green); font-size: 13px; font-family: 'JetBrains Mono', monospace; margin-top: 4px; }
    .actions { display: flex; gap: 10px; }
    button { background: var(--bg-panel); color: #fff; border: 1px solid var(--border); padding: 8px 16px; border-radius: 8px; font-size: 13px; font-weight: 600; cursor: pointer; transition: all 0.2s; display: inline-flex; align-items: center; gap: 6px; }
    button:hover { background: var(--accent-cyan); color: #000; border-color: var(--accent-cyan); transform: translateY(-1px); }
    button.btn-amber:hover { background: var(--accent-amber); color: #000; border-color: var(--accent-amber); }
    
    .metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }
    .card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; padding: 20px; box-shadow: 0 4px 20px rgba(0,0,0,0.2); }
    .card h3 { font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color: var(--text-muted); margin-bottom: 10px; }
    .card .val { font-size: 32px; font-weight: 700; font-family: 'JetBrains Mono', monospace; }
    
    .grid-main { display: grid; grid-template-columns: 2fr 1fr; gap: 24px; }
    .section-title { font-size: 15px; font-weight: 600; margin-bottom: 14px; display: flex; justify-content: space-between; align-items: center; }
    
    table { width: 100%; border-collapse: collapse; font-family: 'JetBrains Mono', monospace; font-size: 12px; }
    th { text-align: left; padding: 12px 14px; color: var(--text-muted); font-size: 11px; font-weight: 600; border-bottom: 1px solid var(--border); }
    td { padding: 10px 14px; border-bottom: 1px solid rgba(255,255,255,0.03); }
    tr:hover { background: rgba(255,255,255,0.02); }
    
    .badge { padding: 3px 8px; border-radius: 4px; font-size: 10px; font-weight: 700; text-transform: uppercase; }
    .badge-zone { background: rgba(0, 210, 255, 0.15); color: var(--accent-cyan); }
    .badge-cache { background: rgba(38, 222, 129, 0.15); color: var(--accent-green); }
    .badge-upstream { background: rgba(165, 94, 234, 0.15); color: var(--accent-purple); }
    .badge-blocked { background: rgba(255, 77, 109, 0.15); color: var(--accent-red); }
    
    .rcode-noerror { color: var(--accent-green); font-weight: 600; }
    .rcode-nxdomain { color: var(--accent-amber); font-weight: 600; }
    .rcode-error { color: var(--accent-red); font-weight: 600; }
    
    .query-box { display: flex; gap: 8px; margin-bottom: 16px; }
    .query-box input { flex: 1; background: var(--bg-panel); border: 1px solid var(--border); padding: 8px 14px; border-radius: 6px; color: #fff; font-family: 'JetBrains Mono', monospace; font-size: 12px; }
    .query-box select { background: var(--bg-panel); border: 1px solid var(--border); color: #fff; padding: 8px 10px; border-radius: 6px; font-size: 12px; }
    .query-result { background: var(--bg-panel); padding: 12px; border-radius: 8px; font-family: 'JetBrains Mono', monospace; font-size: 11px; max-height: 180px; overflow-y: auto; display: none; }
  </style>
</head>
<body>

  <div class="header">
    <div class="header-title">
      <h1>DNS Server & Resolver Dashboard</h1>
      <p id="serverSubtitle">Loading server state...</p>
    </div>
    <div class="actions">
      <button class="btn-amber" onclick="flushCache()">⚡ Flush Cache</button>
      <button onclick="addQuickRecord()">+ Add Local Record</button>
    </div>
  </div>

  <div class="metrics">
    <div class="card">
      <h3>Total Queries</h3>
      <div class="val" id="totalQueries" style="color: var(--accent-cyan)">0</div>
    </div>
    <div class="card">
      <h3>Cache Hit Ratio</h3>
      <div class="val" id="cacheRatio" style="color: var(--accent-green)">0.0%</div>
    </div>
    <div class="card">
      <h3>Blocked Ad/Malware</h3>
      <div class="val" id="blockedQueries" style="color: var(--accent-red)">0</div>
    </div>
    <div class="card">
      <h3>Queries / Minute</h3>
      <div class="val" id="qpm" style="color: var(--accent-purple)">0</div>
    </div>
    <div class="card">
      <h3>Upstream Queries</h3>
      <div class="val" id="upstreamQueries" style="color: var(--accent-amber)">0</div>
    </div>
  </div>

  <div class="grid-main">
    <div class="card" style="padding: 0; overflow: hidden;">
      <div style="padding: 16px 20px; border-bottom: 1px solid var(--border);" class="section-title">
        <span>Live DNS Query Log</span>
        <span style="font-size: 11px; color: var(--accent-green);">● LIVE UPDATING</span>
      </div>
      <div style="max-height: 480px; overflow-y: auto;">
        <table>
          <thead>
            <tr>
              <th>TIME</th>
              <th>CLIENT</th>
              <th>DOMAIN</th>
              <th>TYPE</th>
              <th>STATUS</th>
              <th>SOURCE</th>
              <th>LATENCY</th>
            </tr>
          </thead>
          <tbody id="logTableBody">
            <tr><td colspan="7" style="text-align: center; color: var(--text-muted);">Waiting for queries...</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <div style="display: flex; flex-direction: column; gap: 20px;">
      <!-- Interactive Query Box -->
      <div class="card">
        <div class="section-title">Test DNS Resolver</div>
        <div class="query-box">
          <input type="text" id="testDomain" value="www.mycompany.local" placeholder="e.g. www.mycompany.local" />
          <select id="testType">
            <option value="A">A</option>
            <option value="AAAA">AAAA</option>
            <option value="CNAME">CNAME</option>
            <option value="MX">MX</option>
            <option value="TXT">TXT</option>
          </select>
          <button onclick="runTestQuery()">Resolve</button>
        </div>
        <div id="queryResult" class="query-result"></div>
      </div>

      <!-- Top Queried -->
      <div class="card">
        <div class="section-title">Top Queried Domains</div>
        <table>
          <thead><tr><th>DOMAIN</th><th style="text-align: right;">HITS</th></tr></thead>
          <tbody id="topQueriedBody">
            <tr><td colspan="2" style="color: var(--text-muted);">No queries recorded yet</td></tr>
          </tbody>
        </table>
      </div>

      <!-- Top Blocked -->
      <div class="card">
        <div class="section-title">Top Blocked Domains</div>
        <table>
          <thead><tr><th>DOMAIN</th><th style="text-align: right;">BLOCKED</th></tr></thead>
          <tbody id="topBlockedBody">
            <tr><td colspan="2" style="color: var(--text-muted);">No blocked requests</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <script>
    async function updateDashboard() {
      try {
        const statsRes = await fetch('/api/stats');
        const stats = await statsRes.json();

        document.getElementById('serverSubtitle').innerText = 
          `UDP/TCP DNS: Port ${stats.dnsPort}  |  Authoritative Zone: ${stats.zone}  |  Web UI: Port 5380`;
        document.getElementById('totalQueries').innerText = stats.totalQueries.toLocaleString();
        document.getElementById('cacheRatio').innerText = stats.cacheHitRatio + '%';
        document.getElementById('blockedQueries').innerText = stats.blockedQueries.toLocaleString();
        document.getElementById('qpm').innerText = stats.qpm;
        document.getElementById('upstreamQueries').innerText = stats.upstreamQueries.toLocaleString();

        // Top Queried
        const tqBody = document.getElementById('topQueriedBody');
        if (stats.topQueried.length > 0) {
          tqBody.innerHTML = stats.topQueried.map(q => 
            `<tr><td style="color: var(--accent-cyan);">${q.domain}</td><td style="text-align: right; font-weight: 700;">${q.count}</td></tr>`
          ).join('');
        }

        // Top Blocked
        const tbBody = document.getElementById('topBlockedBody');
        if (stats.topBlocked.length > 0) {
          tbBody.innerHTML = stats.topBlocked.map(b => 
            `<tr><td style="color: var(--accent-red);">${b.domain}</td><td style="text-align: right; font-weight: 700;">${b.count}</td></tr>`
          ).join('');
        }

        // Live logs
        const logsRes = await fetch('/api/logs');
        const logs = await logsRes.json();
        const logBody = document.getElementById('logTableBody');
        if (logs.length > 0) {
          logBody.innerHTML = logs.slice(-25).reverse().map(l => {
            const badgeClass = l.source === 'ZONE' ? 'badge-zone' :
                               l.source === 'CACHE' ? 'badge-cache' :
                               l.source === 'UPSTREAM' ? 'badge-upstream' : 'badge-blocked';
            const rcodeClass = l.rcode === 'NOERROR' ? 'rcode-noerror' :
                               l.rcode === 'NXDOMAIN' ? 'rcode-nxdomain' : 'rcode-error';
            return `<tr>
              <td>${l.time}</td>
              <td style="color: var(--text-muted);">${l.client}</td>
              <td style="font-weight: 600;">${l.domain}</td>
              <td>${l.type}</td>
              <td class="${rcodeClass}">${l.rcode}</td>
              <td><span class="badge ${badgeClass}">${l.source}</span></td>
              <td style="color: var(--text-muted);">${l.latency}ms</td>
            </tr>`;
          }).join('');
        }
      } catch (err) {
        console.error("Dashboard refresh error:", err);
      }
    }

    async function flushCache() {
      await fetch('/api/flush', { method: 'POST' });
      alert('DNS Cache successfully flushed!');
      updateDashboard();
    }

    async function addQuickRecord() {
      const domain = prompt('Enter domain name:', 'test.mycompany.local');
      if (!domain) return;
      const val = prompt('Enter IP/target value:', '192.168.1.199');
      if (!val) return;

      const body = `domain=${encodeURIComponent(domain)}&type=A&ttl=3600&val=${encodeURIComponent(val)}`;
      await fetch('/api/records', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: body
      });
      alert('Record added successfully to authoritative zone!');
      updateDashboard();
    }

    async function runTestQuery() {
      const domain = document.getElementById('testDomain').value.trim();
      const type = document.getElementById('testType').value;
      const resDiv = document.getElementById('queryResult');
      resDiv.style.display = 'block';
      resDiv.innerText = 'Querying resolver...';

      try {
        const res = await fetch(`/api/query?domain=${encodeURIComponent(domain)}&type=${type}`);
        const data = await res.json();
        let out = `Status: ${data.rcode} (AA=${data.aa}, RA=${data.ra})\\n`;
        if (data.answers.length > 0) {
          out += 'Answers:\\n';
          data.answers.forEach(a => {
            out += ` • ${a.name}  ${a.ttl}s  ${a.type}  ->  ${a.value}\\n`;
          });
        } else {
          out += 'No answer records returned.';
        }
        resDiv.innerText = out;
        updateDashboard();
      } catch (e) {
        resDiv.innerText = 'Query failed: ' + e.message;
      }
    }

    updateDashboard();
    setInterval(updateDashboard, 1500);
  </script>
</body>
</html>
""";
    }
}
