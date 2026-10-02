package com.dns.protocol;

import java.util.Objects;

/**
 * Represents a DNS Question in a query or response message (RFC 1035 Section 4.1.2).
 */
public class DnsQuestion {

    public static final int CLASS_IN = 1; // Internet class

    private final String name;
    private final RecordType type;
    private final int qClass;

    public DnsQuestion(String name, RecordType type, int qClass) {
        this.name = normalizeName(name);
        this.type = type != null ? type : RecordType.A;
        this.qClass = qClass;
    }

    public DnsQuestion(String name, RecordType type) {
        this(name, type, CLASS_IN);
    }

    public static String normalizeName(String name) {
        if (name == null || name.isEmpty() || name.equals(".")) {
            return ".";
        }
        String clean = name.trim().toLowerCase();
        if (clean.endsWith(".") && clean.length() > 1) {
            clean = clean.substring(0, clean.length() - 1);
        }
        return clean;
    }

    public String getName() {
        return name;
    }

    public RecordType getType() {
        return type;
    }

    public int getQClass() {
        return qClass;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof DnsQuestion that)) return false;
        return qClass == that.qClass &&
                Objects.equals(name, that.name) &&
                type == that.type;
    }

    @Override
    public int hashCode() {
        return Objects.hash(name, type, qClass);
    }

    @Override
    public String toString() {
        return String.format("%s.\t\tIN\t%s", name, type.getName());
    }
}
