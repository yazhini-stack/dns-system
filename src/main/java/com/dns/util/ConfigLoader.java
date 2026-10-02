package com.dns.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

/**
 * Loads configuration properties for the DNS server with intelligent defaults.
 */
public class ConfigLoader {

    private final Properties properties = new Properties();

    public ConfigLoader() {
        this("config/dns.properties");
    }

    public ConfigLoader(String configPath) {
        load(configPath);
    }

    private void load(String path) {
        // Try multiple candidate paths (relative to CWD, inside dns-system/, or classpath)
        List<File> candidates = List.of(
                new File(path),
                new File("dns-system", path),
                new File("..", path)
        );

        boolean loaded = false;
        for (File candidate : candidates) {
            if (candidate.exists() && candidate.isFile()) {
                try (InputStream in = new FileInputStream(candidate)) {
                    properties.load(in);
                    Logger.info("Loaded configuration from: " + candidate.getAbsolutePath());
                    loaded = true;
                    break;
                } catch (IOException e) {
                    Logger.warn("Could not read configuration file: " + candidate.getPath() + " (" + e.getMessage() + ")");
                }
            }
        }

        if (!loaded) {
            // Try classpath
            try (InputStream in = getClass().getClassLoader().getResourceAsStream(path)) {
                if (in != null) {
                    properties.load(in);
                    Logger.info("Loaded configuration from classpath resource: " + path);
                    loaded = true;
                }
            } catch (IOException ignored) {}
        }

        if (!loaded) {
            Logger.info("Using built-in defaults (config file not found at " + path + ")");
        }
    }

    public int getInt(String key, int defaultValue) {
        String val = properties.getProperty(key);
        if (val != null) {
            try {
                return Integer.parseInt(val.trim());
            } catch (NumberFormatException ignored) {}
        }
        return defaultValue;
    }

    public long getLong(String key, long defaultValue) {
        String val = properties.getProperty(key);
        if (val != null) {
            try {
                return Long.parseLong(val.trim());
            } catch (NumberFormatException ignored) {}
        }
        return defaultValue;
    }

    public boolean getBoolean(String key, boolean defaultValue) {
        String val = properties.getProperty(key);
        if (val != null) {
            return Boolean.parseBoolean(val.trim());
        }
        return defaultValue;
    }

    public String getString(String key, String defaultValue) {
        return properties.getProperty(key, defaultValue).trim();
    }

    public List<String> getStringList(String key, List<String> defaultValues) {
        String val = properties.getProperty(key);
        if (val == null || val.trim().isEmpty()) {
            return defaultValues;
        }
        String[] parts = val.split(",");
        List<String> result = new ArrayList<>();
        for (String p : parts) {
            String trimmed = p.trim();
            if (!trimmed.isEmpty()) {
                result.add(trimmed);
            }
        }
        return result.isEmpty() ? defaultValues : result;
    }

    // Typed configuration getters
    private Integer overridePort = null;
    public void setServerPort(int port) { this.overridePort = port; }
    public int getServerPort() { return overridePort != null ? overridePort : getInt("server.port", 5353); }
    public String getServerHost() { return getString("server.host", "0.0.0.0"); }
    public boolean isTcpEnabled() { return getBoolean("server.tcp.enabled", true); }
    public List<String> getUpstreamServers() {
        return getStringList("upstream.servers", List.of("8.8.8.8:53", "1.1.1.1:53"));
    }
    public int getUpstreamTimeoutMs() { return getInt("upstream.timeout.ms", 2000); }
    public int getCacheMaxSize() { return getInt("cache.max_size", 10000); }
    public int getNegativeTtlSeconds() { return getInt("cache.negative_ttl_seconds", 300); }
    public boolean isCacheEnabled() { return getBoolean("cache.enabled", true); }
    public boolean isBlockingEnabled() { return getBoolean("blocking.enabled", true); }
    public String getBlockingMode() { return getString("blocking.mode", "ip"); } // "ip" or "nxdomain"
    public String getBlockingIp4() { return getString("blocking.ip4", "0.0.0.0"); }
    public String getBlockingIp6() { return getString("blocking.ip6", "::"); }
    public String getBlocklistPath() { return getString("blocking.filepath", "blocklists/sample.txt"); }
    public String getZonePath() { return getString("zone.filepath", "zones/local.zone"); }
    public boolean isRateLimitEnabled() { return getBoolean("ratelimit.enabled", true); }
    public int getRateLimitRps() { return getInt("ratelimit.requests_per_second", 50); }
    public int getThreadPoolSize() { return getInt("threads.pool_size", 16); }
    public String getLogFilePath() { return getString("log.filepath", "logs/dns-queries.log"); }
}
