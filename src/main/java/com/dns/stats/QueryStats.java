package com.dns.stats;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Thread-safe metric collection for DNS queries, cache efficacy, and latency.
 */
public class QueryStats {

    private final AtomicLong totalQueries = new AtomicLong(0);
    private final AtomicLong cacheHits = new AtomicLong(0);
    private final AtomicLong cacheMisses = new AtomicLong(0);
    private final AtomicLong blockedQueries = new AtomicLong(0);
    private final AtomicLong authoritativeQueries = new AtomicLong(0);
    private final AtomicLong upstreamQueries = new AtomicLong(0);
    private final AtomicLong rateLimitedQueries = new AtomicLong(0);
    private final AtomicLong errorQueries = new AtomicLong(0);

    // Domain frequency maps
    private final Map<String, AtomicLong> topQueriedDomains = new ConcurrentHashMap<>();
    private final Map<String, AtomicLong> topBlockedDomains = new ConcurrentHashMap<>();

    // Sliding window for Queries Per Minute (QPM)
    private static final int BUCKET_COUNT = 60; // 60 1-second buckets
    private final long[] qpmBuckets = new long[BUCKET_COUNT];
    private final long[] bucketTimestamps = new long[BUCKET_COUNT];

    public void recordQuery(String domain, String source, boolean blocked, boolean error) {
        totalQueries.incrementAndGet();

        long nowSec = System.currentTimeMillis() / 1000L;
        int bucketIndex = (int) (nowSec % BUCKET_COUNT);
        synchronized (qpmBuckets) {
            if (bucketTimestamps[bucketIndex] != nowSec) {
                bucketTimestamps[bucketIndex] = nowSec;
                qpmBuckets[bucketIndex] = 0;
            }
            qpmBuckets[bucketIndex]++;
        }

        if (domain != null && !domain.isEmpty()) {
            topQueriedDomains.computeIfAbsent(domain.toLowerCase(), k -> new AtomicLong(0)).incrementAndGet();
            if (blocked) {
                topBlockedDomains.computeIfAbsent(domain.toLowerCase(), k -> new AtomicLong(0)).incrementAndGet();
            }
        }

        if (blocked) {
            blockedQueries.incrementAndGet();
        } else if ("CACHE".equalsIgnoreCase(source)) {
            cacheHits.incrementAndGet();
        } else if ("ZONE".equalsIgnoreCase(source)) {
            authoritativeQueries.incrementAndGet();
        } else if ("UPSTREAM".equalsIgnoreCase(source)) {
            upstreamQueries.incrementAndGet();
            cacheMisses.incrementAndGet();
        }

        if (error) {
            errorQueries.incrementAndGet();
        }
    }

    public void recordRateLimited() {
        rateLimitedQueries.incrementAndGet();
    }

    public long getTotalQueries() { return totalQueries.get(); }
    public long getCacheHits() { return cacheHits.get(); }
    public long getCacheMisses() { return cacheMisses.get(); }
    public long getBlockedQueries() { return blockedQueries.get(); }
    public long getAuthoritativeQueries() { return authoritativeQueries.get(); }
    public long getUpstreamQueries() { return upstreamQueries.get(); }
    public long getRateLimitedQueries() { return rateLimitedQueries.get(); }
    public long getErrorQueries() { return errorQueries.get(); }

    public double getCacheHitRatio() {
        long h = cacheHits.get();
        long m = cacheMisses.get();
        long total = h + m;
        return total == 0 ? 0.0 : (double) h / total;
    }

    public int getQueriesPerMinute() {
        long nowSec = System.currentTimeMillis() / 1000L;
        long sum = 0;
        synchronized (qpmBuckets) {
            for (int i = 0; i < BUCKET_COUNT; i++) {
                if (nowSec - bucketTimestamps[i] < 60) {
                    sum += qpmBuckets[i];
                }
            }
        }
        return (int) sum;
    }

    public static class DomainCount {
        private final String domain;
        private final long count;

        public DomainCount(String domain, long count) {
            this.domain = domain;
            this.count = count;
        }

        public String getDomain() { return domain; }
        public long getCount() { return count; }
    }

    public List<DomainCount> getTopQueried(int limit) {
        return getTopFromMap(topQueriedDomains, limit);
    }

    public List<DomainCount> getTopBlocked(int limit) {
        return getTopFromMap(topBlockedDomains, limit);
    }

    private List<DomainCount> getTopFromMap(Map<String, AtomicLong> map, int limit) {
        List<DomainCount> list = new ArrayList<>();
        for (Map.Entry<String, AtomicLong> entry : map.entrySet()) {
            list.add(new DomainCount(entry.getKey(), entry.getValue().get()));
        }
        list.sort(Comparator.comparingLong(DomainCount::getCount).reversed());
        return list.size() > limit ? list.subList(0, limit) : list;
    }

    public void reset() {
        totalQueries.set(0);
        cacheHits.set(0);
        cacheMisses.set(0);
        blockedQueries.set(0);
        authoritativeQueries.set(0);
        upstreamQueries.set(0);
        rateLimitedQueries.set(0);
        errorQueries.set(0);
        topQueriedDomains.clear();
        topBlockedDomains.clear();
        synchronized (qpmBuckets) {
            for (int i = 0; i < BUCKET_COUNT; i++) {
                qpmBuckets[i] = 0;
                bucketTimestamps[i] = 0;
            }
        }
    }
}
