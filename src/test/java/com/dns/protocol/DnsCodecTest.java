package com.dns.protocol;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class DnsCodecTest {

    @Test
    @DisplayName("Encode and decode standard A query")
    void testEncodeDecodeQuery() throws Exception {
        DnsMessage query = DnsMessage.createQuery(0x1234, "www.example.com", RecordType.A, true);
        byte[] wire = DnsCodec.encode(query);

        assertNotNull(wire);
        assertTrue(wire.length > 12);

        DnsMessage decoded = DnsCodec.decode(wire);
        assertEquals(0x1234, decoded.getHeader().getId());
        assertFalse(decoded.getHeader().isQr());
        assertTrue(decoded.getHeader().isRd());
        assertEquals(1, decoded.getQuestions().size());

        DnsQuestion q = decoded.getQuestions().get(0);
        assertEquals("www.example.com", q.getName());
        assertEquals(RecordType.A, q.getType());
        assertEquals(1, q.getQClass());
    }

    @Test
    @DisplayName("Encode and decode response with multiple record types (A, AAAA, CNAME, MX, TXT)")
    void testEncodeDecodeResponse() throws Exception {
        DnsMessage query = DnsMessage.createQuery(0xABCD, "example.com", RecordType.A, true);
        DnsMessage response = DnsMessage.createSuccessResponse(query);
        response.getHeader().setAa(true);
        response.getHeader().setRa(true);

        response.addAnswer(DnsRecord.createA("example.com", 300, "93.184.216.34"));
        response.addAnswer(DnsRecord.createAAAA("example.com", 300, "2606:2800:220:1:248:1863:25c8:19e6"));
        response.addAnswer(DnsRecord.createCNAME("alias.example.com", 300, "example.com"));
        response.addAnswer(DnsRecord.createMX("example.com", 600, 10, "mail.example.com"));
        response.addAnswer(DnsRecord.createTXT("example.com", 300, "v=spf1 -all"));
        response.addAuthority(DnsRecord.createNS("example.com", 86400, "ns1.example.com"));
        response.addAdditional(DnsRecord.createA("ns1.example.com", 86400, "198.51.100.1"));

        byte[] wire = DnsCodec.encode(response);
        DnsMessage decoded = DnsCodec.decode(wire);

        assertEquals(0xABCD, decoded.getHeader().getId());
        assertTrue(decoded.getHeader().isQr());
        assertTrue(decoded.getHeader().isAa());
        assertTrue(decoded.getHeader().isRa());
        assertEquals(DnsHeader.RCODE_NOERROR, decoded.getHeader().getRcode());

        assertEquals(1, decoded.getQuestions().size());
        assertEquals(5, decoded.getAnswers().size());
        assertEquals(1, decoded.getAuthorities().size());
        assertEquals(1, decoded.getAdditionals().size());

        // Verify A record
        DnsRecord aRec = decoded.getAnswers().get(0);
        assertEquals("example.com", aRec.getName());
        assertEquals(RecordType.A, aRec.getType());
        assertEquals(300, aRec.getTtl());
        assertEquals("93.184.216.34", aRec.getParsedValue());

        // Verify AAAA record
        DnsRecord aaaaRec = decoded.getAnswers().get(1);
        assertEquals(RecordType.AAAA, aaaaRec.getType());
        assertEquals(InetAddress.getByName("2606:2800:220:1:248:1863:25c8:19e6").getHostAddress(),
                InetAddress.getByName(aaaaRec.getParsedValue()).getHostAddress());

        // Verify CNAME record
        DnsRecord cnameRec = decoded.getAnswers().get(2);
        assertEquals(RecordType.CNAME, cnameRec.getType());
        assertEquals("example.com", cnameRec.getParsedValue());

        // Verify MX record
        DnsRecord mxRec = decoded.getAnswers().get(3);
        assertEquals(RecordType.MX, mxRec.getType());
        assertEquals("10 mail.example.com", mxRec.getParsedValue());

        // Verify TXT record
        DnsRecord txtRec = decoded.getAnswers().get(4);
        assertEquals(RecordType.TXT, txtRec.getType());
        assertEquals("\"v=spf1 -all\"", txtRec.getParsedValue());

        // Verify Authority NS
        DnsRecord nsRec = decoded.getAuthorities().get(0);
        assertEquals(RecordType.NS, nsRec.getType());
        assertEquals("ns1.example.com", nsRec.getParsedValue());
    }

    @Test
    @DisplayName("Verify RFC 1035 Name Compression pointer generation and byte size savings")
    void testNameCompression() throws Exception {
        DnsMessage query = DnsMessage.createQuery(0x4444, "test.sub.domain.example.com", RecordType.A, true);
        DnsMessage response = DnsMessage.createSuccessResponse(query);

        // Add 5 records all sharing the suffix "sub.domain.example.com"
        response.addAnswer(DnsRecord.createA("host1.sub.domain.example.com", 300, "10.0.0.1"));
        response.addAnswer(DnsRecord.createA("host2.sub.domain.example.com", 300, "10.0.0.2"));
        response.addAnswer(DnsRecord.createA("host3.sub.domain.example.com", 300, "10.0.0.3"));
        response.addAnswer(DnsRecord.createA("host4.sub.domain.example.com", 300, "10.0.0.4"));
        response.addAnswer(DnsRecord.createA("host5.sub.domain.example.com", 300, "10.0.0.5"));

        byte[] wire = DnsCodec.encode(response);

        // Check that compression pointers (bytes with 0xC0) are present in the wire data
        boolean foundPointer = false;
        for (int i = 12; i < wire.length - 1; i++) {
            if ((wire[i] & 0xC0) == 0xC0) {
                foundPointer = true;
                break;
            }
        }
        assertTrue(foundPointer, "Expected wire format to contain 0xC0 compression pointers");

        // Decode back and ensure full fidelity
        DnsMessage decoded = DnsCodec.decode(wire);
        assertEquals(5, decoded.getAnswers().size());
        assertEquals("host1.sub.domain.example.com", decoded.getAnswers().get(0).getName());
        assertEquals("host5.sub.domain.example.com", decoded.getAnswers().get(4).getName());
        assertEquals("10.0.0.5", decoded.getAnswers().get(4).getParsedValue());
    }

    @Test
    @DisplayName("Protection against infinite loop in compression pointers")
    void testPointerLoopDetection() {
        // Construct a packet with a pointer pointing to itself (offset 12 -> points to 12)
        byte[] maliciousPacket = new byte[]{
                0x00, 0x01,             // ID
                0x01, 0x00,             // Flags (Standard query, RD)
                0x00, 0x01,             // QDCOUNT = 1
                0x00, 0x00,             // ANCOUNT = 0
                0x00, 0x00,             // NSCOUNT = 0
                0x00, 0x00,             // ARCOUNT = 0
                (byte) 0xC0, 0x0C,      // Pointer to offset 12 (itself!)
                0x00, 0x01,             // QTYPE = A
                0x00, 0x01              // QCLASS = IN
        };

        assertThrows(DnsCodec.DnsParseException.class, () -> DnsCodec.decode(maliciousPacket));
    }

    @Test
    @DisplayName("Handle malformed / truncated packet gracefully")
    void testMalformedPacketHandling() {
        // Only 4 bytes (less than 12-byte header)
        byte[] truncated = new byte[]{0x12, 0x34, 0x01, 0x00};
        assertThrows(DnsCodec.DnsParseException.class, () -> DnsCodec.decode(truncated));
    }
}
