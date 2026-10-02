package com.dns.protocol;

/**
 * Represents the 12-byte DNS message header according to RFC 1035 Section 4.1.1.
 */
public class DnsHeader {

    // Standard RCODE constants
    public static final int RCODE_NOERROR = 0;
    public static final int RCODE_FORMERR = 1;
    public static final int RCODE_SERVFAIL = 2;
    public static final int RCODE_NXDOMAIN = 3;
    public static final int RCODE_NOTIMP = 4;
    public static final int RCODE_REFUSED = 5;

    // Standard Opcode constants
    public static final int OPCODE_QUERY = 0;
    public static final int OPCODE_IQUERY = 1;
    public static final int OPCODE_STATUS = 2;

    private int id;              // 16-bit transaction ID
    private boolean qr;          // Query (0) or Response (1)
    private int opcode;          // 4-bit operation code (0 = standard query)
    private boolean aa;          // Authoritative Answer
    private boolean tc;          // Truncation flag
    private boolean rd;          // Recursion Desired
    private boolean ra;          // Recursion Available
    private int z;               // 3-bit reserved (must be 0)
    private int rcode;           // 4-bit response code

    private int qdCount;         // Number of questions
    private int anCount;         // Number of answers
    private int nsCount;         // Number of authority records
    private int arCount;         // Number of additional records

    public DnsHeader() {
        this.opcode = OPCODE_QUERY;
        this.rcode = RCODE_NOERROR;
    }

    public DnsHeader(int id) {
        this();
        this.id = id;
    }

    // Getters and Setters
    public int getId() { return id; }
    public void setId(int id) { this.id = id & 0xFFFF; }

    public boolean isQr() { return qr; }
    public void setQr(boolean qr) { this.qr = qr; }

    public int getOpcode() { return opcode; }
    public void setOpcode(int opcode) { this.opcode = opcode & 0x0F; }

    public boolean isAa() { return aa; }
    public void setAa(boolean aa) { this.aa = aa; }

    public boolean isTc() { return tc; }
    public void setTc(boolean tc) { this.tc = tc; }

    public boolean isRd() { return rd; }
    public void setRd(boolean rd) { this.rd = rd; }

    public boolean isRa() { return ra; }
    public void setRa(boolean ra) { this.ra = ra; }

    public int getZ() { return z; }
    public void setZ(int z) { this.z = z & 0x07; }

    public int getRcode() { return rcode; }
    public void setRcode(int rcode) { this.rcode = rcode & 0x0F; }

    public int getQdCount() { return qdCount; }
    public void setQdCount(int qdCount) { this.qdCount = qdCount & 0xFFFF; }

    public int getAnCount() { return anCount; }
    public void setAnCount(int anCount) { this.anCount = anCount & 0xFFFF; }

    public int getNsCount() { return nsCount; }
    public void setNsCount(int nsCount) { this.nsCount = nsCount & 0xFFFF; }

    public int getArCount() { return arCount; }
    public void setArCount(int arCount) { this.arCount = arCount & 0xFFFF; }

    /**
     * Converts the header flags to a 16-bit integer representation.
     */
    public int getFlagsAsInt() {
        int flags = 0;
        if (qr) flags |= (1 << 15);
        flags |= ((opcode & 0x0F) << 11);
        if (aa) flags |= (1 << 10);
        if (tc) flags |= (1 << 9);
        if (rd) flags |= (1 << 8);
        if (ra) flags |= (1 << 7);
        flags |= ((z & 0x07) << 4);
        flags |= (rcode & 0x0F);
        return flags;
    }

    /**
     * Sets the header flags from a 16-bit integer.
     */
    public void setFlagsFromInt(int flags) {
        this.qr = ((flags >> 15) & 1) == 1;
        this.opcode = (flags >> 11) & 0x0F;
        this.aa = ((flags >> 10) & 1) == 1;
        this.tc = ((flags >> 9) & 1) == 1;
        this.rd = ((flags >> 8) & 1) == 1;
        this.ra = ((flags >> 7) & 1) == 1;
        this.z = (flags >> 4) & 0x07;
        this.rcode = flags & 0x0F;
    }

    public static String rcodeToString(int rcode) {
        return switch (rcode) {
            case RCODE_NOERROR -> "NOERROR";
            case RCODE_FORMERR -> "FORMERR";
            case RCODE_SERVFAIL -> "SERVFAIL";
            case RCODE_NXDOMAIN -> "NXDOMAIN";
            case RCODE_NOTIMP -> "NOTIMP";
            case RCODE_REFUSED -> "REFUSED";
            default -> "RCODE_" + rcode;
        };
    }

    @Override
    public String toString() {
        return String.format(
            "DnsHeader[id=0x%04X, qr=%s, opcode=%d, aa=%s, tc=%s, rd=%s, ra=%s, rcode=%s(%d), qd=%d, an=%d, ns=%d, ar=%d]",
            id, qr ? "RESPONSE" : "QUERY", opcode, aa, tc, rd, ra, rcodeToString(rcode), rcode, qdCount, anCount, nsCount, arCount
        );
    }
}
