package com.dns.protocol;

import java.util.HashMap;
import java.util.Map;

/**
 * Standard DNS Resource Record Types (RFC 1035, RFC 3596).
 */
public enum RecordType {
    A(1, "A"),
    NS(2, "NS"),
    CNAME(5, "CNAME"),
    SOA(6, "SOA"),
    PTR(12, "PTR"),
    MX(15, "MX"),
    TXT(16, "TXT"),
    AAAA(28, "AAAA"),
    ANY(255, "ANY"),
    UNKNOWN(0, "UNKNOWN");

    private final int code;
    private final String name;

    private static final Map<Integer, RecordType> BY_CODE = new HashMap<>();
    private static final Map<String, RecordType> BY_NAME = new HashMap<>();

    static {
        for (RecordType type : values()) {
            if (type != UNKNOWN) {
                BY_CODE.put(type.code, type);
                BY_NAME.put(type.name.toUpperCase(), type);
            }
        }
    }

    RecordType(int code, String name) {
        this.code = code;
        this.name = name;
    }

    public int getCode() {
        return code;
    }

    public String getName() {
        return name;
    }

    public static RecordType fromCode(int code) {
        return BY_CODE.getOrDefault(code, UNKNOWN);
    }

    public static RecordType fromName(String name) {
        if (name == null) return UNKNOWN;
        return BY_NAME.getOrDefault(name.trim().toUpperCase(), UNKNOWN);
    }

    @Override
    public String toString() {
        return name;
    }
}
