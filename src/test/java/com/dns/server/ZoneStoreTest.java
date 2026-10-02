package com.dns.server;

import com.dns.protocol.DnsRecord;
import com.dns.protocol.RecordType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ZoneStoreTest {

    private ZoneStore zoneStore;

    @BeforeEach
    void setUp() {
        zoneStore = new ZoneStore("zones/local.zone");
    }

    @Test
    @DisplayName("Zone authority verification")
    void testIsAuthoritative() {
        assertTrue(zoneStore.isAuthoritative("mycompany.local"));
        assertTrue(zoneStore.isAuthoritative("www.mycompany.local"));
        assertTrue(zoneStore.isAuthoritative("deep.sub.mycompany.local"));
        assertFalse(zoneStore.isAuthoritative("google.com"));
        assertFalse(zoneStore.isAuthoritative("othercompany.com"));
    }

    @Test
    @DisplayName("Lookup A and AAAA records in local zone")
    void testLookupAAndAAAA() {
        List<DnsRecord> aRecs = zoneStore.lookup("www.mycompany.local", RecordType.A);
        assertNotNull(aRecs);
        assertFalse(aRecs.isEmpty());
        assertEquals("192.168.1.50", aRecs.get(0).getParsedValue());

        List<DnsRecord> aaaaRecs = zoneStore.lookup("api.mycompany.local", RecordType.AAAA);
        assertNotNull(aaaaRecs);
        assertFalse(aaaaRecs.isEmpty());
        assertEquals(RecordType.AAAA, aaaaRecs.get(0).getType());
    }

    @Test
    @DisplayName("Lookup CNAME alias record")
    void testLookupCNAME() {
        List<DnsRecord> cnameRecs = zoneStore.lookup("web.mycompany.local", RecordType.CNAME);
        assertNotNull(cnameRecs);
        assertFalse(cnameRecs.isEmpty());
        assertEquals(RecordType.CNAME, cnameRecs.get(0).getType());
        assertEquals("www.mycompany.local", cnameRecs.get(0).getParsedValue());
    }

    @Test
    @DisplayName("Lookup MX and TXT records")
    void testLookupMxAndTxt() {
        List<DnsRecord> mxRecs = zoneStore.lookup("mycompany.local", RecordType.MX);
        assertNotNull(mxRecs);
        assertFalse(mxRecs.isEmpty());
        assertEquals(RecordType.MX, mxRecs.get(0).getType());

        List<DnsRecord> txtRecs = zoneStore.lookup("mycompany.local", RecordType.TXT);
        assertNotNull(txtRecs);
        assertFalse(txtRecs.isEmpty());
        assertEquals(RecordType.TXT, txtRecs.get(0).getType());
    }

    @Test
    @DisplayName("Non-existent host in authoritative zone returns null for NXDOMAIN")
    void testNonExistentHostInZone() {
        List<DnsRecord> recs = zoneStore.lookup("ghost.mycompany.local", RecordType.A);
        assertNull(recs, "Expected null indicating NXDOMAIN within authoritative zone");
    }

    @Test
    @DisplayName("Dynamic record addition at runtime")
    void testDynamicRecordAddition() {
        DnsRecord dynamicRecord = DnsRecord.createA("dynamic.mycompany.local", 3600, "192.168.1.200");
        zoneStore.addRecord(dynamicRecord);

        List<DnsRecord> recs = zoneStore.lookup("dynamic.mycompany.local", RecordType.A);
        assertNotNull(recs);
        assertEquals(1, recs.size());
        assertEquals("192.168.1.200", recs.get(0).getParsedValue());
    }
}
