package com.dns.stats;

import com.dns.protocol.RecordType;
import com.dns.util.Logger;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Logs DNS queries to a file and provides real-time event notifications for the GUI.
 */
public class QueryLogger {

    public static class LogEntry {
        private final LocalDateTime timestamp;
        private final String clientIp;
        private final String domain;
        private final RecordType recordType;
        private final String rcode;
        private final String source; // "ZONE", "CACHE", "UPSTREAM", "BLOCKED", "RATE_LIMIT"
        private final long latencyMs;

        public LogEntry(LocalDateTime timestamp, String clientIp, String domain,
                        RecordType recordType, String rcode, String source, long latencyMs) {
            this.timestamp = timestamp;
            this.clientIp = clientIp;
            this.domain = domain;
            this.recordType = recordType;
            this.rcode = rcode;
            this.source = source;
            this.latencyMs = latencyMs;
        }

        public LocalDateTime getTimestamp() { return timestamp; }
        public String getClientIp() { return clientIp; }
        public String getDomain() { return domain; }
        public RecordType getRecordType() { return recordType; }
        public String getRcode() { return rcode; }
        public String getSource() { return source; }
        public long getLatencyMs() { return latencyMs; }

        public String getFormattedTime() {
            return timestamp.format(DateTimeFormatter.ofPattern("HH:mm:ss.SSS"));
        }

        @Override
        public String toString() {
            return String.format("[%s] %s -> %s %s [%s] (%s, %dms)",
                    getFormattedTime(), clientIp, domain, recordType, rcode, source, latencyMs);
        }
    }

    public interface LogListener {
        void onNewLogEntry(LogEntry entry);
    }

    private static final int MAX_BUFFER_SIZE = 1000;
    private final LinkedList<LogEntry> recentEntries = new LinkedList<>();
    private final List<LogListener> listeners = new CopyOnWriteArrayList<>();
    private final File logFile;
    private final ExecutorService fileWriterExecutor = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "dns-file-logger");
        t.setDaemon(true);
        return t;
    });

    public QueryLogger(String logFilePath) {
        File f = new File(logFilePath);
        if (!f.isAbsolute()) {
            // Check dns-system relative or cwd
            if (new File("dns-system").exists()) {
                f = new File("dns-system", logFilePath);
            }
        }
        this.logFile = f;
        initFile();
    }

    private void initFile() {
        try {
            File parent = logFile.getParentFile();
            if (parent != null && !parent.exists()) {
                parent.mkdirs();
            }
            if (!logFile.exists()) {
                logFile.createNewFile();
            }
        } catch (IOException e) {
            Logger.warn("Failed to create log file: " + logFile.getAbsolutePath() + " (" + e.getMessage() + ")");
        }
    }

    public void addListener(LogListener listener) {
        listeners.add(listener);
    }

    public void removeListener(LogListener listener) {
        listeners.remove(listener);
    }

    public void log(String clientIp, String domain, RecordType recordType,
                    String rcode, String source, long latencyMs) {
        LogEntry entry = new LogEntry(
                LocalDateTime.now(), clientIp, domain, recordType, rcode, source, latencyMs
        );

        synchronized (recentEntries) {
            if (recentEntries.size() >= MAX_BUFFER_SIZE) {
                recentEntries.removeFirst();
            }
            recentEntries.addLast(entry);
        }

        // Notify listeners
        for (LogListener listener : listeners) {
            try {
                listener.onNewLogEntry(entry);
            } catch (Exception ignored) {}
        }

        // Write to log file asynchronously
        fileWriterExecutor.submit(() -> appendToFile(entry));
    }

    private void appendToFile(LogEntry entry) {
        try (BufferedWriter bw = new BufferedWriter(new FileWriter(logFile, true))) {
            bw.write(entry.toString());
            bw.newLine();
        } catch (IOException e) {
            // Avoid recursion in logger
        }
    }

    public List<LogEntry> getRecentEntries() {
        synchronized (recentEntries) {
            return new ArrayList<>(recentEntries);
        }
    }
}
