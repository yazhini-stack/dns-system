package com.dns.server;

import com.dns.cache.DnsCache;
import com.dns.filter.BlockList;
import com.dns.protocol.DnsHeader;
import com.dns.protocol.DnsMessage;
import com.dns.protocol.DnsQuestion;
import com.dns.protocol.DnsRecord;
import com.dns.protocol.RecordType;
import com.dns.resolver.RecursiveResolver;
import com.dns.stats.QueryLogger;
import com.dns.stats.QueryStats;
import com.dns.util.ConfigLoader;
import com.dns.util.Logger;

import java.net.InetAddress;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Coordinates DNS resolution pipeline: Rate Limiting -> Blocklist -> Zone Store -> Cache -> Upstream Resolver.
 */
public class QueryHandler {

    private final ConfigLoader config;
    private final ZoneStore zoneStore;
    private final BlockList blockList;
    private final DnsCache cache;
    private final RecursiveResolver recursiveResolver;
    private final QueryStats stats;
    private final QueryLogger logger;

    // Rate limiting tracking
    private final Map<String, ClientRateBucket> rateLimiters = new ConcurrentHashMap<>();

    public QueryHandler(ConfigLoader config, ZoneStore zoneStore, BlockList blockList,
                        DnsCache cache, RecursiveResolver recursiveResolver,
                        QueryStats stats, QueryLogger logger) {
        this.config = config;
        this.zoneStore = zoneStore;
        this.blockList = blockList;
        this.cache = cache;
        this.recursiveResolver = recursiveResolver;
        this.stats = stats;
        this.logger = logger;
    }

    /**
     * Processes an incoming DNS query message and generates an RFC-compliant response.
     */
    public DnsMessage handleQuery(DnsMessage query, InetAddress clientAddress) {
        long startTime = System.currentTimeMillis();
        String clientIp = clientAddress != null ? clientAddress.getHostAddress() : "127.0.0.1";

        // 1. Rate Limiting Check
        if (config.isRateLimitEnabled() && isRateLimited(clientIp)) {
            stats.recordRateLimited();
            long latency = System.currentTimeMillis() - startTime;
            logger.log(clientIp, "RATE_LIMITED", RecordType.UNKNOWN, "REFUSED", "RATE_LIMIT", latency);
            DnsMessage resp = DnsMessage.createRefusedResponse(query);
            resp.getHeader().setRa(true);
            return resp;
        }

        // 2. Validate Questions
        if (query == null || query.getQuestions().isEmpty()) {
            long latency = System.currentTimeMillis() - startTime;
            logger.log(clientIp, "MALFORMED", RecordType.UNKNOWN, "FORMERR", "SERVER", latency);
            stats.recordQuery("MALFORMED", "SERVER", false, true);
            return DnsMessage.createFormErrResponse(query);
        }

        DnsQuestion question = query.getQuestions().get(0);
        String domain = question.getName();
        RecordType type = question.getType();

        // 3. Blocklist Filtering
        if (config.isBlockingEnabled() && blockList.isBlocked(domain)) {
            DnsMessage response = createBlockedResponse(query, domain, type);
            long latency = System.currentTimeMillis() - startTime;
            stats.recordQuery(domain, "BLOCKED", true, false);
            logger.log(clientIp, domain, type, DnsHeader.rcodeToString(response.getHeader().getRcode()), "BLOCKED", latency);
            return response;
        }

        // 4. Authoritative Zone Lookup
        if (zoneStore.isAuthoritative(domain)) {
            List<DnsRecord> zoneRecords = zoneStore.lookup(domain, type);
            DnsMessage response;
            if (zoneRecords == null) {
                // Authoritative NXDOMAIN
                response = DnsMessage.createNxDomainResponse(query);
            } else {
                // Authoritative NOERROR (either answers found or NODATA)
                response = DnsMessage.createSuccessResponse(query);
                for (DnsRecord rec : zoneRecords) {
                    response.addAnswer(rec);
                }
            }
            response.getHeader().setAa(true); // Authoritative Answer
            response.getHeader().setRa(true); // Recursion Available

            long latency = System.currentTimeMillis() - startTime;
            stats.recordQuery(domain, "ZONE", false, false);
            logger.log(clientIp, domain, type, DnsHeader.rcodeToString(response.getHeader().getRcode()), "ZONE", latency);
            return response;
        }

        // 5. Cache Lookup
        if (config.isCacheEnabled()) {
            DnsCache.CacheEntry cached = cache.get(domain, type);
            if (cached != null) {
                DnsMessage response;
                if (cached.isNegative()) {
                    response = DnsMessage.createNxDomainResponse(query);
                } else {
                    response = DnsMessage.createSuccessResponse(query);
                    for (DnsRecord rec : cached.getRecordsWithRemainingTtl()) {
                        response.addAnswer(rec);
                    }
                }
                response.getHeader().setRa(true);

                long latency = System.currentTimeMillis() - startTime;
                stats.recordQuery(domain, "CACHE", false, false);
                logger.log(clientIp, domain, type, DnsHeader.rcodeToString(response.getHeader().getRcode()), "CACHE", latency);
                return response;
            }
        }

        // 6. Upstream Recursive Resolution
        if (query.getHeader().isRd() && recursiveResolver != null) {
            try {
                DnsMessage upstreamResp = recursiveResolver.resolve(query);
                if (upstreamResp != null) {
                    int rcode = upstreamResp.getHeader().getRcode();

                    if (config.isCacheEnabled()) {
                        if (rcode == DnsHeader.RCODE_NOERROR && !upstreamResp.getAnswers().isEmpty()) {
                            cache.put(domain, type, upstreamResp.getAnswers());
                        } else if (rcode == DnsHeader.RCODE_NXDOMAIN) {
                            cache.putNegative(domain, type, rcode);
                        }
                    }

                    long latency = System.currentTimeMillis() - startTime;
                    stats.recordQuery(domain, "UPSTREAM", false, false);
                    logger.log(clientIp, domain, type, DnsHeader.rcodeToString(rcode), "UPSTREAM", latency);
                    return upstreamResp;
                }
            } catch (Exception e) {
                Logger.warn("Recursive resolution error for " + domain + ": " + e.getMessage());
            }

            // Upstream resolution failed -> return SERVFAIL
            DnsMessage servfail = DnsMessage.createServFailResponse(query);
            servfail.getHeader().setRa(true);
            long latency = System.currentTimeMillis() - startTime;
            stats.recordQuery(domain, "UPSTREAM", false, true);
            logger.log(clientIp, domain, type, "SERVFAIL", "UPSTREAM", latency);
            return servfail;
        }

        // 7. Non-recursive query for non-authoritative domain -> return empty response with RA=1
        DnsMessage nonRecResp = DnsMessage.createSuccessResponse(query);
        nonRecResp.getHeader().setRa(true);
        long latency = System.currentTimeMillis() - startTime;
        stats.recordQuery(domain, "UPSTREAM", false, false);
        logger.log(clientIp, domain, type, "NOERROR", "UPSTREAM", latency);
        return nonRecResp;
    }

    private DnsMessage createBlockedResponse(DnsMessage query, String domain, RecordType type) {
        String mode = config.getBlockingMode();
        if ("nxdomain".equalsIgnoreCase(mode)) {
            DnsMessage resp = DnsMessage.createNxDomainResponse(query);
            resp.getHeader().setRa(true);
            return resp;
        }

        // Default "ip" mode: return 0.0.0.0 (A) or :: (AAAA)
        DnsMessage resp = DnsMessage.createSuccessResponse(query);
        resp.getHeader().setRa(true);
        long sinkholeTtl = 300;

        if (type == RecordType.A || type == RecordType.ANY) {
            resp.addAnswer(DnsRecord.createA(domain, sinkholeTtl, config.getBlockingIp4()));
        } else if (type == RecordType.AAAA) {
            resp.addAnswer(DnsRecord.createAAAA(domain, sinkholeTtl, config.getBlockingIp6()));
        }
        return resp;
    }

    private boolean isRateLimited(String clientIp) {
        int maxRps = config.getRateLimitRps();
        long nowSec = System.currentTimeMillis() / 1000L;
        ClientRateBucket bucket = rateLimiters.computeIfAbsent(clientIp, k -> new ClientRateBucket());
        return bucket.incrementAndCheck(nowSec, maxRps);
    }

    private static class ClientRateBucket {
        private long currentSecond = 0;
        private final AtomicInteger count = new AtomicInteger(0);

        public synchronized boolean incrementAndCheck(long nowSec, int maxRps) {
            if (nowSec != currentSecond) {
                currentSecond = nowSec;
                count.set(0);
            }
            return count.incrementAndGet() > maxRps;
        }
    }

    public ZoneStore getZoneStore() { return zoneStore; }
    public BlockList getBlockList() { return blockList; }
    public DnsCache getCache() { return cache; }
    public QueryStats getStats() { return stats; }
    public QueryLogger getLogger() { return logger; }
}
