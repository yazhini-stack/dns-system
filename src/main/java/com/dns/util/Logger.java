package com.dns.util;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Lightweight, thread-safe console logger with clean formatting.
 */
public class Logger {

    public enum Level {
        DEBUG(0, "\u001B[36m"), // Cyan
        INFO(1, "\u001B[32m"),  // Green
        WARN(2, "\u001B[33m"),  // Yellow
        ERROR(3, "\u001B[31m"); // Red

        final int priority;
        final String color;

        Level(int priority, String color) {
            this.priority = priority;
            this.color = color;
        }
    }

    private static final String RESET = "\u001B[0m";
    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS");
    private static volatile Level currentLevel = Level.INFO;

    public static void setLevel(Level level) {
        currentLevel = level;
    }

    public static void debug(String format, Object... args) {
        log(Level.DEBUG, format, args);
    }

    public static void info(String format, Object... args) {
        log(Level.INFO, format, args);
    }

    public static void warn(String format, Object... args) {
        log(Level.WARN, format, args);
    }

    public static void error(String format, Object... args) {
        log(Level.ERROR, format, args);
    }

    public static void error(String message, Throwable t) {
        log(Level.ERROR, message + " - " + t.getMessage());
        t.printStackTrace(System.err);
    }

    private static synchronized void log(Level level, String format, Object... args) {
        if (level.priority < currentLevel.priority) {
            return;
        }
        String timestamp = LocalDateTime.now().format(FORMATTER);
        String message = (args == null || args.length == 0) ? format : String.format(format, args);
        String threadName = Thread.currentThread().getName();
        System.out.printf("[%s] [%s%s%s] [%s] %s%n",
                timestamp, level.color, level.name(), RESET, threadName, message);
    }
}
