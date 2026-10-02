package com.dns.protocol;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Low-level DNS Wire Format Encoder and Decoder (RFC 1035).
 * Implements full name compression pointer parsing (0xC0xx) and generation.
 */
public class DnsCodec {

    public static final int HEADER_SIZE = 12;
    public static final int MAX_UDP_PAYLOAD_SIZE = 512;
    private static final int MAX_POINTER_JUMPS = 16;

    public static class DnsParseException extends IOException {
        public DnsParseException(String message) {
            super(message);
        }
        public DnsParseException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /**
     * Encodes a DnsMessage into standard DNS wire-format bytes.
     */
    public static byte[] encode(DnsMessage message) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        Map<String, Integer> compressionMap = new HashMap<>();

        DnsHeader header = message.getHeader();
        // Update counts in header
        header.setQdCount(message.getQuestions().size());
        header.setAnCount(message.getAnswers().size());
        header.setNsCount(message.getAuthorities().size());
        header.setArCount(message.getAdditionals().size());

        // 1. Header (12 bytes)
        writeHeader(baos, header);

        // 2. Questions
        for (DnsQuestion question : message.getQuestions()) {
            writeDomainName(baos, question.getName(), compressionMap);
            write16(baos, question.getType().getCode());
            write16(baos, question.getQClass());
        }

        // 3. Answers
        for (DnsRecord answer : message.getAnswers()) {
            writeRecord(baos, answer, compressionMap);
        }

        // 4. Authorities
        for (DnsRecord auth : message.getAuthorities()) {
            writeRecord(baos, auth, compressionMap);
        }

        // 5. Additionals
        for (DnsRecord add : message.getAdditionals()) {
            writeRecord(baos, add, compressionMap);
        }

        return baos.toByteArray();
    }

    private static void writeHeader(ByteArrayOutputStream baos, DnsHeader header) {
        write16(baos, header.getId());
        write16(baos, header.getFlagsAsInt());
        write16(baos, header.getQdCount());
        write16(baos, header.getAnCount());
        write16(baos, header.getNsCount());
        write16(baos, header.getArCount());
    }

    private static void writeRecord(ByteArrayOutputStream baos, DnsRecord record, Map<String, Integer> compressionMap) {
        writeDomainName(baos, record.getName(), compressionMap);
        write16(baos, record.getType().getCode());
        write16(baos, record.getRClass());
        write32(baos, record.getTtl());

        byte[] rdata = record.getRdata();
        RecordType type = record.getType();

        // Compress domain names inside RDATA for domain-referencing types
        if (type == RecordType.CNAME || type == RecordType.NS || type == RecordType.PTR) {
            String domain = record.getParsedValue();
            if (domain != null && !domain.isEmpty() && !domain.startsWith("[")) {
                ByteArrayOutputStream rdataStream = new ByteArrayOutputStream();
                writeDomainName(rdataStream, domain, compressionMap, baos.size() + 2);
                byte[] compBytes = rdataStream.toByteArray();
                write16(baos, compBytes.length);
                baos.writeBytes(compBytes);
                return;
            }
        } else if (type == RecordType.MX && rdata.length >= 2) {
            int pref = ((rdata[0] & 0xFF) << 8) | (rdata[1] & 0xFF);
            String exchange = record.getParsedValue();
            if (exchange != null && exchange.contains(" ")) {
                exchange = exchange.substring(exchange.indexOf(' ') + 1);
            }
            if (exchange != null && !exchange.isEmpty()) {
                ByteArrayOutputStream rdataStream = new ByteArrayOutputStream();
                write16(rdataStream, pref);
                writeDomainName(rdataStream, exchange, compressionMap, baos.size() + 2);
                byte[] compBytes = rdataStream.toByteArray();
                write16(baos, compBytes.length);
                baos.writeBytes(compBytes);
                return;
            }
        }

        // Standard raw RDATA write
        write16(baos, rdata.length);
        baos.writeBytes(rdata);
    }

    private static void writeDomainName(ByteArrayOutputStream baos, String domain, Map<String, Integer> compressionMap) {
        writeDomainName(baos, domain, compressionMap, 0);
    }

    private static void writeDomainName(ByteArrayOutputStream baos, String domain,
                                        Map<String, Integer> compressionMap, int offsetDelta) {
        String clean = DnsQuestion.normalizeName(domain);
        if (clean.equals(".")) {
            baos.write(0);
            return;
        }

        String current = clean;
        while (!current.isEmpty()) {
            if (compressionMap.containsKey(current)) {
                int pointerOffset = compressionMap.get(current);
                // 14-bit offset with top 2 bits set to 11
                int pointer = 0xC000 | (pointerOffset & 0x3FFF);
                write16(baos, pointer);
                return;
            }

            int currentOffset = baos.size() + offsetDelta;
            if (currentOffset < 0x3FFF) {
                compressionMap.put(current, currentOffset);
            }

            int dotIndex = current.indexOf('.');
            String label;
            if (dotIndex != -1) {
                label = current.substring(0, dotIndex);
                current = current.substring(dotIndex + 1);
            } else {
                label = current;
                current = "";
            }

            byte[] labelBytes = label.getBytes(StandardCharsets.US_ASCII);
            if (labelBytes.length > 63) {
                throw new IllegalArgumentException("Label length exceeds 63 characters: " + label);
            }
            baos.write(labelBytes.length);
            baos.writeBytes(labelBytes);
        }
        baos.write(0); // Root label null terminator
    }

    private static void write16(ByteArrayOutputStream baos, int value) {
        baos.write((value >> 8) & 0xFF);
        baos.write(value & 0xFF);
    }

    private static void write32(ByteArrayOutputStream baos, long value) {
        baos.write((int) ((value >> 24) & 0xFF));
        baos.write((int) ((value >> 16) & 0xFF));
        baos.write((int) ((value >> 8) & 0xFF));
        baos.write((int) (value & 0xFF));
    }

    /**
     * Decodes a DNS wire-format byte array into a DnsMessage.
     */
    public static DnsMessage decode(byte[] data) throws DnsParseException {
        return decode(data, 0, data.length);
    }

    public static DnsMessage decode(byte[] data, int offset, int length) throws DnsParseException {
        if (data == null || length < HEADER_SIZE || offset + length > data.length) {
            throw new DnsParseException("Packet too short for DNS header: " + (data == null ? 0 : length) + " bytes");
        }

        PacketReader reader = new PacketReader(data, offset, length);

        // 1. Decode Header
        int id = reader.readUnsignedShort();
        int flags = reader.readUnsignedShort();
        int qdCount = reader.readUnsignedShort();
        int anCount = reader.readUnsignedShort();
        int nsCount = reader.readUnsignedShort();
        int arCount = reader.readUnsignedShort();

        DnsHeader header = new DnsHeader(id);
        header.setFlagsFromInt(flags);
        header.setQdCount(qdCount);
        header.setAnCount(anCount);
        header.setNsCount(nsCount);
        header.setArCount(arCount);

        DnsMessage message = new DnsMessage(header);

        // 2. Decode Questions
        for (int i = 0; i < qdCount; i++) {
            String qname = reader.readDomainName();
            int qtype = reader.readUnsignedShort();
            int qclass = reader.readUnsignedShort();
            message.addQuestion(new DnsQuestion(qname, RecordType.fromCode(qtype), qclass));
        }

        // 3. Decode Answers
        for (int i = 0; i < anCount; i++) {
            message.addAnswer(reader.readRecord());
        }

        // 4. Decode Authorities
        for (int i = 0; i < nsCount; i++) {
            message.addAuthority(reader.readRecord());
        }

        // 5. Decode Additionals
        for (int i = 0; i < arCount; i++) {
            message.addAdditional(reader.readRecord());
        }

        return message;
    }

    /**
     * Helper class for reading DNS wire data with bounds checking and pointer decompression.
     */
    private static class PacketReader {
        private final byte[] buffer;
        private final int messageOffset;
        private final int limit;
        private int pos;

        public PacketReader(byte[] buffer, int offset, int length) {
            this(buffer, offset, offset, offset + length);
        }

        public PacketReader(byte[] buffer, int messageOffset, int currentPos, int limit) {
            this.buffer = buffer;
            this.messageOffset = messageOffset;
            this.pos = currentPos;
            this.limit = limit;
        }

        public int readUnsignedByte() throws DnsParseException {
            if (pos >= limit) {
                throw new DnsParseException("Unexpected end of packet at byte " + pos);
            }
            return buffer[pos++] & 0xFF;
        }

        public int readUnsignedShort() throws DnsParseException {
            int b1 = readUnsignedByte();
            int b2 = readUnsignedByte();
            return (b1 << 8) | b2;
        }

        public long readUnsignedInt() throws DnsParseException {
            long b1 = readUnsignedByte();
            long b2 = readUnsignedByte();
            long b3 = readUnsignedByte();
            long b4 = readUnsignedByte();
            return (b1 << 24) | (b2 << 16) | (b3 << 8) | b4;
        }

        public byte[] readBytes(int length) throws DnsParseException {
            if (length < 0 || pos + length > limit) {
                throw new DnsParseException("Cannot read " + length + " bytes, packet ends at " + limit);
            }
            byte[] dest = new byte[length];
            System.arraycopy(buffer, pos, dest, 0, length);
            pos += length;
            return dest;
        }

        /**
         * Reads a domain name, following compression pointers (0xC0xx).
         */
        public String readDomainName() throws DnsParseException {
            StringBuilder sb = new StringBuilder();
            int currentPos = this.pos;
            boolean jumped = false;
            int jumps = 0;
            Set<Integer> visitedPointers = new HashSet<>();

            while (true) {
                if (currentPos >= limit) {
                    throw new DnsParseException("Premature end of packet while parsing domain name");
                }
                int len = buffer[currentPos] & 0xFF;

                if (len == 0) {
                    if (!jumped) {
                        this.pos = currentPos + 1;
                    }
                    break;
                }

                // Check for compression pointer (top two bits 11)
                if ((len & 0xC0) == 0xC0) {
                    if (currentPos + 1 >= limit) {
                        throw new DnsParseException("Incomplete compression pointer");
                    }
                    int b2 = buffer[currentPos + 1] & 0xFF;
                    int pointerOffset = messageOffset + (((len & 0x3F) << 8) | b2);

                    if (visitedPointers.contains(pointerOffset)) {
                        throw new DnsParseException("Pointer loop detected at offset " + pointerOffset);
                    }
                    visitedPointers.add(pointerOffset);

                    if (++jumps > MAX_POINTER_JUMPS) {
                        throw new DnsParseException("Exceeded max pointer jumps (" + MAX_POINTER_JUMPS + ")");
                    }

                    if (pointerOffset >= limit || pointerOffset < messageOffset) {
                        throw new DnsParseException("Compression pointer out of bounds: " + pointerOffset);
                    }

                    if (!jumped) {
                        this.pos = currentPos + 2;
                        jumped = true;
                    }
                    currentPos = pointerOffset;
                } else if ((len & 0xC0) == 0) {
                    // Normal label
                    currentPos++;
                    if (currentPos + len > limit) {
                        throw new DnsParseException("Label length extends beyond packet limit");
                    }
                    String label = new String(buffer, currentPos, len, StandardCharsets.US_ASCII);
                    currentPos += len;
                    if (sb.length() > 0) sb.append(".");
                    sb.append(label);
                    if (!jumped) {
                        this.pos = currentPos;
                    }
                } else {
                    throw new DnsParseException("Illegal label format: 0x" + Integer.toHexString(len));
                }
            }

            return sb.length() == 0 ? "." : sb.toString();
        }

        public DnsRecord readRecord() throws DnsParseException {
            String name = readDomainName();
            int typeCode = readUnsignedShort();
            int rclass = readUnsignedShort();
            long ttl = readUnsignedInt();
            int rdlength = readUnsignedShort();

            RecordType type = RecordType.fromCode(typeCode);
            int rdataStart = this.pos;

            // Parse RDATA according to type
            byte[] rawRdata = readBytes(rdlength);
            DnsRecord record = new DnsRecord(name, type, rclass, ttl, rawRdata);

            try {
                if (type == RecordType.A && rdlength == 4) {
                    record.setParsedValue(InetAddress.getByAddress(rawRdata).getHostAddress());
                } else if (type == RecordType.AAAA && rdlength == 16) {
                    record.setParsedValue(InetAddress.getByAddress(rawRdata).getHostAddress());
                } else if (type == RecordType.CNAME || type == RecordType.NS || type == RecordType.PTR) {
                    PacketReader subReader = new PacketReader(buffer, messageOffset, rdataStart, limit);
                    String target = subReader.readDomainName();
                    record.setParsedValue(target);
                } else if (type == RecordType.MX && rdlength >= 3) {
                    int pref = ((rawRdata[0] & 0xFF) << 8) | (rawRdata[1] & 0xFF);
                    PacketReader subReader = new PacketReader(buffer, messageOffset, rdataStart + 2, limit);
                    String exchange = subReader.readDomainName();
                    record.setParsedValue(pref + " " + exchange);
                } else if (type == RecordType.TXT) {
                    StringBuilder sb = new StringBuilder();
                    int idx = 0;
                    while (idx < rawRdata.length) {
                        int len = rawRdata[idx++] & 0xFF;
                        if (idx + len <= rawRdata.length) {
                            if (sb.length() > 0) sb.append(" ");
                            sb.append("\"").append(new String(rawRdata, idx, len, StandardCharsets.UTF_8)).append("\"");
                            idx += len;
                        } else {
                            break;
                        }
                    }
                    record.setParsedValue(sb.toString());
                } else if (type == RecordType.SOA) {
                    PacketReader subReader = new PacketReader(buffer, messageOffset, rdataStart, limit);
                    String mname = subReader.readDomainName();
                    String rname = subReader.readDomainName();
                    long serial = subReader.readUnsignedInt();
                    long refresh = subReader.readUnsignedInt();
                    long retry = subReader.readUnsignedInt();
                    long expire = subReader.readUnsignedInt();
                    long minimum = subReader.readUnsignedInt();
                    record.setParsedValue(String.format("%s %s %d %d %d %d %d", mname, rname, serial, refresh, retry, expire, minimum));
                }
            } catch (Exception ignored) {
                // Keep default raw byte representation if specialized parsing fails
            }

            return record;
        }
    }
}
