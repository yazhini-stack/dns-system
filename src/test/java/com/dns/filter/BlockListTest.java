package com.dns.filter;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class BlockListTest {

    private BlockList blockList;

    @BeforeEach
    void setUp() {
        blockList = new BlockList("non_existent_file.txt"); // Falls back to default rules
        blockList.addRule("ads.example.com");
        blockList.addRule("*.doubleclick.net");
        blockList.addRule("tracker.*");
    }

    @Test
    @DisplayName("Exact domain match is blocked")
    void testExactMatch() {
        assertTrue(blockList.isBlocked("ads.example.com"));
        assertTrue(blockList.isBlocked("ads.example.com."));
        assertTrue(blockList.isBlocked("ADS.EXAMPLE.COM"));
        assertFalse(blockList.isBlocked("notads.example.com"));
    }

    @Test
    @DisplayName("Wildcard subdomain match is blocked")
    void testWildcardMatch() {
        assertTrue(blockList.isBlocked("sub.doubleclick.net"));
        assertTrue(blockList.isBlocked("a.b.doubleclick.net"));
        assertFalse(blockList.isBlocked("notdoubleclick.net"));
    }

    @Test
    @DisplayName("Wildcard suffix match is blocked")
    void testWildcardSuffixMatch() {
        assertTrue(blockList.isBlocked("tracker.org"));
        assertTrue(blockList.isBlocked("tracker.co.uk"));
    }

    @Test
    @DisplayName("Legitimate domain is not blocked")
    void testUnblockedDomain() {
        assertFalse(blockList.isBlocked("google.com"));
        assertFalse(blockList.isBlocked("wikipedia.org"));
        assertFalse(blockList.isBlocked("mycompany.local"));
    }
}
