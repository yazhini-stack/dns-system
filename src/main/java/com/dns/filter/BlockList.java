package com.dns.filter;

import com.dns.protocol.DnsQuestion;
import com.dns.util.Logger;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.regex.Pattern;

/**
 * Manages blocked domains (ad/malware/telemetry) with exact and wildcard matching.
 */
public class BlockList {

    private final Set<String> exactBlockedDomains = new HashSet<>();
    private final List<WildcardMatcher> wildcardMatchers = new CopyOnWriteArrayList<>();
    private final String filepath;

    public BlockList(String filepath) {
        this.filepath = filepath;
        load();
    }

    public synchronized void load() {
        exactBlockedDomains.clear();
        wildcardMatchers.clear();

        List<File> candidates = List.of(
                new File(filepath),
                new File("dns-system", filepath),
                new File("..", filepath)
        );

        File target = null;
        for (File candidate : candidates) {
            if (candidate.exists() && candidate.isFile()) {
                target = candidate;
                break;
            }
        }

        if (target == null) {
            Logger.warn("Blocklist file not found at " + filepath + ", initializing with default blocked domains");
            addDefaultRules();
            return;
        }

        int count = 0;
        try (BufferedReader reader = new BufferedReader(new FileReader(target))) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#") || line.startsWith("//")) {
                    continue;
                }
                addRule(line);
                count++;
            }
            Logger.info("Loaded " + count + " blocklist rules from " + target.getAbsolutePath());
        } catch (IOException e) {
            Logger.error("Failed to read blocklist file: " + target.getAbsolutePath(), e);
            addDefaultRules();
        }
    }

    private void addDefaultRules() {
        addRule("*.doubleclick.net");
        addRule("*.analytics.google.com");
        addRule("*.telemetry.microsoft.com");
        addRule("ads.example.com");
        addRule("*.tracking.adservice.com");
    }

    public synchronized void addRule(String rule) {
        if (rule == null || rule.trim().isEmpty()) return;
        String normalized = rule.trim().toLowerCase();
        // Remove trailing dot if any
        if (normalized.endsWith(".") && normalized.length() > 1) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }

        if (normalized.contains("*")) {
            wildcardMatchers.add(new WildcardMatcher(normalized));
        } else {
            exactBlockedDomains.add(normalized);
        }
    }

    public synchronized boolean isBlocked(String domain) {
        if (domain == null) return false;
        String clean = DnsQuestion.normalizeName(domain);

        // 1. Exact match
        if (exactBlockedDomains.contains(clean)) {
            return true;
        }

        // 2. Wildcard and subdomain match
        for (WildcardMatcher matcher : wildcardMatchers) {
            if (matcher.matches(clean)) {
                return true;
            }
        }

        return false;
    }

    public synchronized int getBlockedCount() {
        return exactBlockedDomains.size() + wildcardMatchers.size();
    }

    public synchronized Set<String> getRules() {
        Set<String> rules = new HashSet<>(exactBlockedDomains);
        for (WildcardMatcher m : wildcardMatchers) {
            rules.add(m.rawPattern);
        }
        return rules;
    }

    /**
     * Wildcard matcher supporting patterns like *.domain.com, domain.*, or sub.*.domain.com
     */
    private static class WildcardMatcher {
        private final String rawPattern;
        private final Pattern regex;

        public WildcardMatcher(String pattern) {
            this.rawPattern = pattern;
            // Convert glob pattern to regex
            StringBuilder sb = new StringBuilder("^");
            for (int i = 0; i < pattern.length(); i++) {
                char c = pattern.charAt(i);
                if (c == '*') {
                    sb.append(".*");
                } else if (c == '.') {
                    sb.append("\\.");
                } else if (c == '?' || c == '+' || c == '(' || c == ')' || c == '[' || c == ']' || c == '^' || c == '$') {
                    sb.append("\\").append(c);
                } else {
                    sb.append(c);
                }
            }
            sb.append("$");
            this.regex = Pattern.compile(sb.toString(), Pattern.CASE_INSENSITIVE);
        }

        public boolean matches(String domain) {
            return regex.matcher(domain).matches();
        }
    }
}
