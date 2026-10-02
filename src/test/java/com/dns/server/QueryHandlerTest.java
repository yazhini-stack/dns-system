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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;

import static org.junit.jupiter.api.Assertions.*;

class QueryHandlerTest {

    private QueryHandler queryHandler;
    private ZoneStore zoneStore;
    private BlockList blockList;
    private DnsCache cache;
    private QueryStats stats;

    @BeforeEach
    void setUp() {
        ConfigLoader config = new ConfigLoader("config/dns.properties");
        zoneStore = new ZoneStore("zones/local.zone");
        blockList = new BlockList("blocklists/sample.txt");
        cache = new DnsCache(1000, 300);
        RecursiveResolver resolver = null; // No upstream in this unit test
        stats = new QueryStats();
        QueryLogger logger = new QueryLogger("logs/test-queries.log");

        queryHandler = new QueryHandler(config, zoneStore, blockList, cache, resolver, stats, logger);
    }

    @Test
    @DisplayName("Handle authoritative query for local zone record")
    void testAuthoritativeQuery() throws Exception {
        DnsMessage query = DnsMessage.createQuery(1, "www.mycompany.local", RecordType.A, true);
        DnsMessage response = queryHandler.handleQuery(query, InetAddress.getByName("127.0.0.1"));

        assertNotNull(response);
        assertEquals(DnsHeader.RCODE_NOERROR, response.getHeader().getRcode());
        assertTrue(response.getHeader().isAa(), "AA bit must be set for authoritative zone");
        assertTrue(response.getHeader().isRa());
        assertFalse(response.getAnswers().isEmpty());
        assertEquals("192.168.1.50", response.getAnswers().get(0).getParsedValue());
        assertEquals(1, stats.getAuthoritativeQueries());
    }

    @Test
    @DisplayName("Handle authoritative NXDOMAIN for non-existent domain in local zone")
    void testAuthoritativeNxDomain() throws Exception {
        DnsMessage query = DnsMessage.createQuery(2, "nosuchhost.mycompany.local", RecordType.A, true);
        DnsMessage response = queryHandler.handleQuery(query, InetAddress.getByName("127.0.0.1"));

        assertNotNull(response);
        assertEquals(DnsHeader.RCODE_NXDOMAIN, response.getHeader().getRcode());
        assertTrue(response.getHeader().isAa());
        assertTrue(response.getAnswers().isEmpty());
    }

    @Test
    @DisplayName("Handle blocked domain query (sinkholing to 0.0.0.0)")
    void testBlockedDomain() throws Exception {
        DnsMessage query = DnsMessage.createQuery(3, "ads.doubleclick.net", RecordType.A, true);
        DnsMessage response = queryHandler.handleQuery(query, InetAddress.getByName("127.0.0.1"));

        assertNotNull(response);
        assertEquals(DnsHeader.RCODE_NOERROR, response.getHeader().getRcode());
        assertFalse(response.getAnswers().isEmpty());
        assertEquals("0.0.0.0", response.getAnswers().get(0).getParsedValue());
        assertEquals(1, stats.getBlockedQueries());
    }

    @Test
    @DisplayName("Cache hit returns cached records without calling upstream")
    void testCacheHit() throws Exception {
        // Pre-populate cache
        cache.put("cached.external.com", RecordType.A,
                java.util.List.of(DnsRecord.createA("cached.external.com", 300, "203.0.113.10")));

        DnsMessage query = DnsMessage.createQuery(4, "cached.external.com", RecordType.A, true);
        DnsMessage response = queryHandler.handleQuery(query, InetAddress.getByName("127.0.0.1"));

        assertNotNull(response);
        assertEquals(DnsHeader.RCODE_NOERROR, response.getHeader().getRcode());
        assertFalse(response.getAnswers().isEmpty());
        assertEquals("203.0.113.10", response.getAnswers().get(0).getParsedValue());
        assertEquals(1, stats.getCacheHits());
    }

    @Test
    @DisplayName("Rate limiting rejects abusive clients with REFUSED")
    void testRateLimiter() throws Exception {
        InetAddress abusiveClient = InetAddress.getByName("10.99.99.99");
        // Limit is 50 rps
        int refusedCount = 0;
        for (int i = 0; i < 70; i++) {
            DnsMessage query = DnsMessage.createQuery(100 + i, "www.mycompany.local", RecordType.A, true);
            DnsMessage response = queryHandler.handleQuery(query, abusiveClient);
            if (response.getHeader().getRcode() == DnsHeader.RCODE_REFUSED) {
                refusedCount++;
            }
        }
        assertTrue(refusedCount > 0, "Rate limiter should refuse queries exceeding 50 RPS");
        assertTrue(stats.getRateLimitedQueries() > 0);
    }
}
