package com.dns.protocol;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * Represents a DNS Resource Record (RFC 1035 Section 4.1.3).
 */
public class DnsRecord {

    public static final int CLASS_IN = 1;

    private final String name;
    private final RecordType type;
    private final int rClass;
    private long ttl; // 32-bit unsigned
    private final byte[] rdata;

    // Parsed representation for quick access and display
    private String parsedValue;

    public DnsRecord(String name, RecordType type, int rClass, long ttl, byte[] rdata) {
        this.name = DnsQuestion.normalizeName(name);
        this.type = type != null ? type : RecordType.UNKNOWN;
        this.rClass = rClass;
        this.ttl = Math.max(0, ttl);
        this.rdata = rdata != null ? rdata.clone() : new byte[0];
    }

    public DnsRecord(String name, RecordType type, long ttl, byte[] rdata) {
        this(name, type, CLASS_IN, ttl, rdata);
    }

    public String getName() {
        return name;
    }

    public RecordType getType() {
        return type;
    }

    public int getRClass() {
        return rClass;
    }

    public long getTtl() {
        return ttl;
    }

    public void setTtl(long ttl) {
        this.ttl = Math.max(0, ttl);
    }

    public byte[] getRdata() {
        return rdata.clone();
    }

    public int getRdLength() {
        return rdata.length;
    }

    public String getParsedValue() {
        if (parsedValue != null) {
            return parsedValue;
        }
        return formatRdata();
    }

    public void setParsedValue(String parsedValue) {
        this.parsedValue = parsedValue;
    }

    // Factory methods for common record types

    public static DnsRecord createA(String name, long ttl, String ip) {
        try {
            InetAddress addr = InetAddress.getByName(ip);
            byte[] bytes = addr.getAddress();
            if (bytes.length != 4) {
                throw new IllegalArgumentException("Not an IPv4 address: " + ip);
            }
            DnsRecord rec = new DnsRecord(name, RecordType.A, ttl, bytes);
            rec.setParsedValue(addr.getHostAddress());
            return rec;
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException("Invalid IPv4 address: " + ip, e);
        }
    }

    public static DnsRecord createAAAA(String name, long ttl, String ip) {
        try {
            InetAddress addr = InetAddress.getByName(ip);
            byte[] bytes = addr.getAddress();
            if (bytes.length != 16) {
                throw new IllegalArgumentException("Not an IPv6 address: " + ip);
            }
            DnsRecord rec = new DnsRecord(name, RecordType.AAAA, ttl, bytes);
            rec.setParsedValue(addr.getHostAddress());
            return rec;
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException("Invalid IPv6 address: " + ip, e);
        }
    }

    public static DnsRecord createCNAME(String name, long ttl, String targetDomain) {
        byte[] wireName = encodeDomainNameNoCompression(targetDomain);
        DnsRecord rec = new DnsRecord(name, RecordType.CNAME, ttl, wireName);
        rec.setParsedValue(DnsQuestion.normalizeName(targetDomain));
        return rec;
    }

    public static DnsRecord createNS(String name, long ttl, String nsDomain) {
        byte[] wireName = encodeDomainNameNoCompression(nsDomain);
        DnsRecord rec = new DnsRecord(name, RecordType.NS, ttl, wireName);
        rec.setParsedValue(DnsQuestion.normalizeName(nsDomain));
        return rec;
    }

    public static DnsRecord createPTR(String name, long ttl, String ptrDomain) {
        byte[] wireName = encodeDomainNameNoCompression(ptrDomain);
        DnsRecord rec = new DnsRecord(name, RecordType.PTR, ttl, wireName);
        rec.setParsedValue(DnsQuestion.normalizeName(ptrDomain));
        return rec;
    }

    public static DnsRecord createTXT(String name, long ttl, String text) {
        byte[] textBytes = text.getBytes(StandardCharsets.UTF_8);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        int offset = 0;
        // TXT records can have multiple character-strings of max 255 bytes each
        while (offset < textBytes.length) {
            int chunkLen = Math.min(255, textBytes.length - offset);
            baos.write(chunkLen);
            baos.write(textBytes, offset, chunkLen);
            offset += chunkLen;
        }
        if (textBytes.length == 0) {
            baos.write(0);
        }
        DnsRecord rec = new DnsRecord(name, RecordType.TXT, ttl, baos.toByteArray());
        rec.setParsedValue("\"" + text + "\"");
        return rec;
    }

    public static DnsRecord createMX(String name, long ttl, int preference, String exchange) {
        byte[] wireName = encodeDomainNameNoCompression(exchange);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write((preference >> 8) & 0xFF);
        baos.write(preference & 0xFF);
        baos.writeBytes(wireName);
        DnsRecord rec = new DnsRecord(name, RecordType.MX, ttl, baos.toByteArray());
        rec.setParsedValue(preference + " " + DnsQuestion.normalizeName(exchange));
        return rec;
    }

    public static DnsRecord createSOA(String name, long ttl, String mname, String rname,
                                      long serial, long refresh, long retry, long expire, long minimum) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        try {
            dos.write(encodeDomainNameNoCompression(mname));
            dos.write(encodeDomainNameNoCompression(rname));
            dos.writeInt((int) serial);
            dos.writeInt((int) refresh);
            dos.writeInt((int) retry);
            dos.writeInt((int) expire);
            dos.writeInt((int) minimum);
        } catch (IOException ignored) {}

        DnsRecord rec = new DnsRecord(name, RecordType.SOA, ttl, baos.toByteArray());
        rec.setParsedValue(String.format("%s %s %d %d %d %d %d",
                DnsQuestion.normalizeName(mname), DnsQuestion.normalizeName(rname),
                serial, refresh, retry, expire, minimum));
        return rec;
    }

    /**
     * Encodes a domain name without compression (sequence of length-prefixed labels ending in 0).
     */
    public static byte[] encodeDomainNameNoCompression(String domain) {
        if (domain == null || domain.isEmpty() || domain.equals(".")) {
            return new byte[]{0};
        }
        String clean = DnsQuestion.normalizeName(domain);
        String[] labels = clean.split("\\.");
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        for (String label : labels) {
            byte[] bytes = label.getBytes(StandardCharsets.US_ASCII);
            baos.write(bytes.length);
            baos.write(bytes, 0, bytes.length);
        }
        baos.write(0);
        return baos.toByteArray();
    }

    private String formatRdata() {
        if (rdata == null || rdata.length == 0) return "";
        try {
            switch (type) {
                case A:
                    if (rdata.length == 4) {
                        return InetAddress.getByAddress(rdata).getHostAddress();
                    }
                    break;
                case AAAA:
                    if (rdata.length == 16) {
                        return InetAddress.getByAddress(rdata).getHostAddress();
                    }
                    break;
                case TXT:
                    StringBuilder sb = new StringBuilder();
                    int idx = 0;
                    while (idx < rdata.length) {
                        int len = rdata[idx++] & 0xFF;
                        if (idx + len <= rdata.length) {
                            if (sb.length() > 0) sb.append(" ");
                            sb.append("\"").append(new String(rdata, idx, len, StandardCharsets.UTF_8)).append("\"");
                            idx += len;
                        } else {
                            break;
                        }
                    }
                    return sb.toString();
                default:
                    break;
            }
        } catch (Exception ignored) {}
        return "[Hex: " + bytesToHex(rdata) + "]";
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof DnsRecord that)) return false;
        return rClass == that.rClass &&
                Objects.equals(name, that.name) &&
                type == that.type &&
                Arrays.equals(rdata, that.rdata);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(name, type, rClass);
        result = 31 * result + Arrays.hashCode(rdata);
        return result;
    }

    @Override
    public String toString() {
        return String.format("%-24s\t%d\tIN\t%-6s\t%s",
                name + ".", ttl, type.getName(), getParsedValue());
    }
}
