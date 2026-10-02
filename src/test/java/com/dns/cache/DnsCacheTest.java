package com.dns.cache;

import com.dns.protocol.DnsHeader;
import com.dns.protocol.DnsRecord;
import com.dns.protocol.RecordType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class DnsCacheTest {

    private DnsCache cache;

    @BeforeEach
    void setUp() {
        cache = new DnsCache(100, 5); // 5 second negative TTL
    }

    @Test
    @DisplayName("Cache put and get with positive record and decreasing remaining TTL")
    void testCachePutAndGet() throws InterruptedException {
        DnsRecord rec = DnsRecord.createA("test.example.com", 10, "1.2.3.4");
        cache.put("test.example.com", RecordType.A, List.of(rec));

        assertEquals(1, cache.size());

        DnsCache.CacheEntry entry = cache.get("test.example.com", RecordType.A);
        assertNotNull(entry);
        assertFalse(entry.isNegative());
        assertEquals(1, entry.getRecordsWithRemainingTtl().size());
        assertEquals("1.2.3.4", entry.getRecordsWithRemainingTtl().get(0).getParsedValue());

        assertEquals(1, cache.getHits());
        assertEquals(0, cache.getMisses());

        // Test non-cached domain
        assertNull(cache.get("other.example.com", RecordType.A));
        assertEquals(1, cache.getMisses());
    }

    @Test
    @DisplayName("Negative caching for NXDOMAIN with negative TTL")
    void testNegativeCaching() {
        cache.putNegative("notfound.example.com", RecordType.A, DnsHeader.RCODE_NXDOMAIN);

        DnsCache.CacheEntry entry = cache.get("notfound.example.com", RecordType.A);
        assertNotNull(entry);
        assertTrue(entry.isNegative());
        assertEquals(DnsHeader.RCODE_NXDOMAIN, entry.getRcode());
        assertTrue(entry.getRemainingTtlSeconds() > 0);
    }

    @Test
    @DisplayName("Cache TTL expiration")
    void testCacheTtlExpiration() throws InterruptedException {
        DnsRecord shortLived = DnsRecord.createA("expire.me", 1, "10.0.0.1"); // 1 second TTL
        cache.put("expire.me", RecordType.A, List.of(shortLived));

        assertNotNull(cache.get("expire.me", RecordType.A));

        // Sleep to let it expire
        Thread.sleep(1200);

        assertNull(cache.get("expire.me", RecordType.A));
    }

    @Test
    @DisplayName("Cache flush removes all entries")
    void testCacheFlush() {
        cache.put("host1.com", RecordType.A, List.of(DnsRecord.createA("host1.com", 60, "1.1.1.1")));
        cache.put("host2.com", RecordType.A, List.of(DnsRecord.createA("host2.com", 60, "2.2.2.2")));
        assertEquals(2, cache.size());

        cache.flush();
        assertEquals(0, cache.size());
        assertNull(cache.get("host1.com", RecordType.A));
    }
}
