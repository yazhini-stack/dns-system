package com.dns.cache;

import com.dns.protocol.DnsQuestion;
import com.dns.protocol.DnsRecord;
import com.dns.protocol.RecordType;
import com.dns.util.Logger;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * High-performance, concurrent TTL-based DNS cache with negative caching (RFC 2308)
 * and dynamic remaining-TTL decrementing.
 */
public class DnsCache {

    public static class CacheKey {
        private final String domain;
        private final RecordType type;

        public CacheKey(String domain, RecordType type) {
            this.domain = DnsQuestion.normalizeName(domain);
            this.type = type != null ? type : RecordType.A;
        }

        public String getDomain() { return domain; }
        public RecordType getType() { return type; }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof CacheKey that)) return false;
            return Objects.equals(domain, that.domain) && type == that.type;
        }

        @Override
        public int hashCode() {
            return Objects.hash(domain, type);
        }

        @Override
        public String toString() {
            return domain + "/" + type;
        }
    }

    public static class CacheEntry {
        private final CacheKey key;
        private final List<DnsRecord> records;
        private final boolean isNegative;
        private final int rcode;
        private final long expirationTimeMs;
        private final long originalTtl;

        public CacheEntry(CacheKey key, List<DnsRecord> records, boolean isNegative, int rcode, long ttlSeconds) {
            this.key = key;
            this.records = records != null ? new ArrayList<>(records) : Collections.emptyList();
            this.isNegative = isNegative;
            this.rcode = rcode;
            this.originalTtl = ttlSeconds;
            this.expirationTimeMs = System.currentTimeMillis() + (ttlSeconds * 1000L);
        }

        public boolean isExpired() {
            return System.currentTimeMillis() >= expirationTimeMs;
        }

        public long getRemainingTtlSeconds() {
            long remaining = (expirationTimeMs - System.currentTimeMillis()) / 1000L;
            return Math.max(1, remaining);
        }

        public List<DnsRecord> getRecordsWithRemainingTtl() {
            long remainingTtl = getRemainingTtlSeconds();
            List<DnsRecord> freshRecords = new ArrayList<>();
            for (DnsRecord r : records) {
                DnsRecord copy = new DnsRecord(r.getName(), r.getType(), r.getRClass(), remainingTtl, r.getRdata());
                copy.setParsedValue(r.getParsedValue());
                freshRecords.add(copy);
            }
            return freshRecords;
        }

        public boolean isNegative() { return isNegative; }
        public int getRcode() { return rcode; }
        public CacheKey getKey() { return key; }
    }

    private final Map<CacheKey, CacheEntry> cache = new ConcurrentHashMap<>();
    private final int maxEntries;
    private final long negativeTtlSeconds;

    // Cache metrics
    private final AtomicLong hits = new AtomicLong(0);
    private final AtomicLong misses = new AtomicLong(0);
    private final AtomicLong evictions = new AtomicLong(0);

    public DnsCache(int maxEntries, long negativeTtlSeconds) {
        this.maxEntries = maxEntries > 0 ? maxEntries : 10000;
        this.negativeTtlSeconds = negativeTtlSeconds > 0 ? negativeTtlSeconds : 300;
    }

    /**
     * Looks up cached records for a domain and record type.
     * Returns null on cache miss or expired entry.
     */
    public CacheEntry get(String domain, RecordType type) {
        CacheKey key = new CacheKey(domain, type);
        CacheEntry entry = cache.get(key);

        if (entry == null) {
            // Also check for ANY query if applicable
            misses.incrementAndGet();
            return null;
        }

        if (entry.isExpired()) {
            cache.remove(key);
            evictions.incrementAndGet();
            misses.incrementAndGet();
            return null;
        }

        hits.incrementAndGet();
        return entry;
    }

    /**
     * Puts positive DNS answer records into the cache.
     */
    public void put(String domain, RecordType type, List<DnsRecord> records) {
        if (records == null || records.isEmpty()) return;

        // Calculate minimum TTL among answers
        long minTtl = Long.MAX_VALUE;
        for (DnsRecord rec : records) {
            if (rec.getTtl() < minTtl) {
                minTtl = rec.getTtl();
            }
        }
        if (minTtl <= 0) {
            return; // Do not cache entries with 0 TTL
        }

        ensureCapacity();
        CacheKey key = new CacheKey(domain, type);
        cache.put(key, new CacheEntry(key, records, false, 0, minTtl));
    }

    /**
     * Puts a negative response (NXDOMAIN) into the cache according to RFC 2308.
     */
    public void putNegative(String domain, RecordType type, int rcode) {
        ensureCapacity();
        CacheKey key = new CacheKey(domain, type);
        cache.put(key, new CacheEntry(key, Collections.emptyList(), true, rcode, negativeTtlSeconds));
    }

    private void ensureCapacity() {
        if (cache.size() >= maxEntries) {
            cleanupExpired();
            if (cache.size() >= maxEntries) {
                // Remove roughly 10% oldest entries
                int toRemove = Math.max(1, maxEntries / 10);
                Iterator<CacheKey> it = cache.keySet().iterator();
                while (it.hasNext() && toRemove > 0) {
                    it.next();
                    it.remove();
                    evictions.incrementAndGet();
                    toRemove--;
                }
            }
        }
    }

    /**
     * Cleans up expired entries.
     */
    public int cleanupExpired() {
        int removed = 0;
        long now = System.currentTimeMillis();
        Iterator<Map.Entry<CacheKey, CacheEntry>> it = cache.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<CacheKey, CacheEntry> entry = it.next();
            if (now >= entry.getValue().expirationTimeMs) {
                it.remove();
                evictions.incrementAndGet();
                removed++;
            }
        }
        return removed;
    }

    public void flush() {
        int size = cache.size();
        cache.clear();
        Logger.info("Flushed DNS cache (" + size + " entries removed)");
    }

    public int size() {
        return cache.size();
    }

    public long getHits() { return hits.get(); }
    public long getMisses() { return misses.get(); }
    public long getEvictions() { return evictions.get(); }

    public double getHitRatio() {
        long h = hits.get();
        long m = misses.get();
        long total = h + m;
        return total == 0 ? 0.0 : (double) h / total;
    }
}
