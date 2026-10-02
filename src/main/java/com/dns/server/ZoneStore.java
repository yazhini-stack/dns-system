package com.dns.server;

import com.dns.protocol.DnsQuestion;
import com.dns.protocol.DnsRecord;
import com.dns.protocol.RecordType;
import com.dns.util.Logger;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Parses and stores DNS Resource Records from a BIND-style zone file.
 * Serves authoritative responses with AA bit set.
 */
public class ZoneStore {

    private final String zoneFilePath;
    private String origin = "mycompany.local";
    private long defaultTtl = 3600;

    // Map: normalized domain -> list of records
    private final Map<String, List<DnsRecord>> recordsByDomain = new ConcurrentHashMap<>();

    public ZoneStore(String zoneFilePath) {
        this.zoneFilePath = zoneFilePath;
        load();
    }

    public synchronized void load() {
        recordsByDomain.clear();

        List<File> candidates = List.of(
                new File(zoneFilePath),
                new File("dns-system", zoneFilePath),
                new File("..", zoneFilePath)
        );

        File target = null;
        for (File candidate : candidates) {
            if (candidate.exists() && candidate.isFile()) {
                target = candidate;
                break;
            }
        }

        if (target == null) {
            Logger.warn("Zone file not found at " + zoneFilePath + ", creating sample in-memory records for " + origin);
            loadDefaults();
            return;
        }

        try (BufferedReader reader = new BufferedReader(new FileReader(target))) {
            StringBuilder multiLineBuffer = new StringBuilder();
            boolean insideParens = false;
            String line;

            while ((line = reader.readLine()) != null) {
                // Strip comments starting with ';'
                int commentIdx = line.indexOf(';');
                if (commentIdx != -1) {
                    line = line.substring(0, commentIdx);
                }
                line = line.trim();
                if (line.isEmpty()) continue;

                if (line.contains("(") && !line.contains(")")) {
                    insideParens = true;
                    multiLineBuffer.append(line.replace("(", " ")).append(" ");
                    continue;
                } else if (insideParens) {
                    if (line.contains(")")) {
                        insideParens = false;
                        multiLineBuffer.append(line.replace(")", " "));
                        parseLine(multiLineBuffer.toString().trim());
                        multiLineBuffer.setLength(0);
                    } else {
                        multiLineBuffer.append(line).append(" ");
                    }
                    continue;
                }

                parseLine(line);
            }
            Logger.info("Loaded " + getTotalRecordsCount() + " records for zone " + origin + " from " + target.getAbsolutePath());
        } catch (IOException e) {
            Logger.error("Failed to load zone file: " + target.getAbsolutePath(), e);
            loadDefaults();
        }
    }

    private void parseLine(String line) {
        String[] tokens = line.split("\\s+");
        if (tokens.length == 0 || tokens[0].isEmpty()) return;

        if (tokens[0].equalsIgnoreCase("$ORIGIN") && tokens.length > 1) {
            this.origin = DnsQuestion.normalizeName(tokens[1]);
            return;
        }

        if (tokens[0].equalsIgnoreCase("$TTL") && tokens.length > 1) {
            try {
                this.defaultTtl = Long.parseLong(tokens[1]);
            } catch (NumberFormatException ignored) {}
            return;
        }

        // Standard record syntax: [name] [ttl] [class] type rdata...
        int idx = 0;
        String nameToken = tokens[idx++];
        String fqdn = resolveFqdn(nameToken);

        long ttl = defaultTtl;
        if (idx < tokens.length && tokens[idx].matches("\\d+")) {
            ttl = Long.parseLong(tokens[idx++]);
        }

        if (idx < tokens.length && tokens[idx].equalsIgnoreCase("IN")) {
            idx++;
        }

        if (idx >= tokens.length) return;
        String typeToken = tokens[idx++];
        RecordType type = RecordType.fromName(typeToken);
        if (type == RecordType.UNKNOWN) return;

        StringBuilder rdataBuilder = new StringBuilder();
        for (int i = idx; i < tokens.length; i++) {
            if (rdataBuilder.length() > 0) rdataBuilder.append(" ");
            rdataBuilder.append(tokens[i]);
        }
        String rdataStr = rdataBuilder.toString().trim();

        try {
            DnsRecord record = createRecordFromZoneEntry(fqdn, type, ttl, rdataStr);
            if (record != null) {
                addRecord(record);
            }
        } catch (Exception e) {
            Logger.warn("Failed to parse zone record line: '" + line + "' (" + e.getMessage() + ")");
        }
    }

    private DnsRecord createRecordFromZoneEntry(String fqdn, RecordType type, long ttl, String rdata) {
        return switch (type) {
            case A -> DnsRecord.createA(fqdn, ttl, rdata);
            case AAAA -> DnsRecord.createAAAA(fqdn, ttl, rdata);
            case CNAME -> DnsRecord.createCNAME(fqdn, ttl, resolveFqdn(rdata));
            case NS -> DnsRecord.createNS(fqdn, ttl, resolveFqdn(rdata));
            case PTR -> DnsRecord.createPTR(fqdn, ttl, resolveFqdn(rdata));
            case TXT -> {
                String cleanTxt = rdata;
                if (cleanTxt.startsWith("\"") && cleanTxt.endsWith("\"") && cleanTxt.length() >= 2) {
                    cleanTxt = cleanTxt.substring(1, cleanTxt.length() - 1);
                }
                yield DnsRecord.createTXT(fqdn, ttl, cleanTxt);
            }
            case MX -> {
                String[] parts = rdata.split("\\s+");
                int pref = Integer.parseInt(parts[0]);
                String exchange = resolveFqdn(parts[1]);
                yield DnsRecord.createMX(fqdn, ttl, pref, exchange);
            }
            case SOA -> {
                String[] parts = rdata.split("\\s+");
                if (parts.length >= 7) {
                    yield DnsRecord.createSOA(fqdn, ttl, resolveFqdn(parts[0]), resolveFqdn(parts[1]),
                            Long.parseLong(parts[2]), Long.parseLong(parts[3]),
                            Long.parseLong(parts[4]), Long.parseLong(parts[5]), Long.parseLong(parts[6]));
                }
                yield null;
            }
            default -> null;
        };
    }

    private String resolveFqdn(String token) {
        if (token == null || token.isEmpty() || token.equals("@")) {
            return origin;
        }
        if (token.endsWith(".")) {
            return DnsQuestion.normalizeName(token);
        }
        return DnsQuestion.normalizeName(token + "." + origin);
    }

    private void loadDefaults() {
        origin = "mycompany.local";
        addRecord(DnsRecord.createSOA(origin, 3600, "ns1." + origin, "admin." + origin, 2026100201L, 3600, 1800, 604800, 86400));
        addRecord(DnsRecord.createNS(origin, 3600, "ns1." + origin));
        addRecord(DnsRecord.createA("ns1." + origin, 3600, "192.168.1.10"));
        addRecord(DnsRecord.createA("www." + origin, 3600, "192.168.1.50"));
        addRecord(DnsRecord.createA("mail." + origin, 3600, "192.168.1.60"));
        addRecord(DnsRecord.createMX(origin, 3600, 10, "mail." + origin));
        addRecord(DnsRecord.createAAAA("api." + origin, 3600, "2001:db8::1"));
        addRecord(DnsRecord.createCNAME("web." + origin, 3600, "www." + origin));
        addRecord(DnsRecord.createTXT(origin, 3600, "v=spf1 mx ~all"));
    }

    public synchronized void addRecord(DnsRecord record) {
        if (record == null) return;
        String normName = DnsQuestion.normalizeName(record.getName());
        recordsByDomain.computeIfAbsent(normName, k -> new CopyOnWriteArrayList<>()).add(record);
    }

    /**
     * Checks if this zone store is authoritative for the given domain.
     */
    public boolean isAuthoritative(String domain) {
        if (domain == null) return false;
        String clean = DnsQuestion.normalizeName(domain);
        return clean.equals(origin) || clean.endsWith("." + origin);
    }

    /**
     * Searches for records matching domain and type.
     * Returns:
     * - List of records if found
     * - CNAME record if an alias exists
     * - Empty list if domain exists in zone but has no records for the type (NODATA)
     * - null if domain does NOT exist in zone at all (authoritative NXDOMAIN)
     */
    public List<DnsRecord> lookup(String domain, RecordType type) {
        String clean = DnsQuestion.normalizeName(domain);
        List<DnsRecord> domainRecords = recordsByDomain.get(clean);

        if (domainRecords == null || domainRecords.isEmpty()) {
            return null; // Not found in zone -> NXDOMAIN
        }

        List<DnsRecord> matches = new ArrayList<>();
        DnsRecord cnameRecord = null;

        for (DnsRecord r : domainRecords) {
            if (r.getType() == RecordType.CNAME) {
                cnameRecord = r;
            }
            if (type == RecordType.ANY || r.getType() == type) {
                matches.add(r);
            }
        }

        if (!matches.isEmpty()) {
            return matches;
        }

        // If specific type not found, but a CNAME is present, return CNAME
        if (cnameRecord != null) {
            return List.of(cnameRecord);
        }

        // Domain exists, but no matching record type (NODATA -> NOERROR with 0 answers)
        return Collections.emptyList();
    }

    public String getOrigin() {
        return origin;
    }

    public int getTotalRecordsCount() {
        int count = 0;
        for (List<DnsRecord> l : recordsByDomain.values()) {
            count += l.size();
        }
        return count;
    }

    public Map<String, List<DnsRecord>> getAllRecords() {
        return Collections.unmodifiableMap(recordsByDomain);
    }
}
