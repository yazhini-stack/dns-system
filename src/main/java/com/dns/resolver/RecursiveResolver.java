package com.dns.resolver;

import com.dns.protocol.DnsHeader;
import com.dns.protocol.DnsMessage;
import com.dns.protocol.DnsQuestion;
import com.dns.protocol.RecordType;
import com.dns.util.Logger;

import java.io.IOException;
import java.util.List;

/**
 * Handles recursive domain resolution by querying upstream DNS forwarders.
 */
public class RecursiveResolver {

    private final UpstreamClient upstreamClient;

    public RecursiveResolver(List<String> upstreamServers, int timeoutMs) {
        this.upstreamClient = new UpstreamClient(upstreamServers, timeoutMs);
    }

    public RecursiveResolver(UpstreamClient upstreamClient) {
        this.upstreamClient = upstreamClient;
    }

    /**
     * Forwards the query to upstream servers recursively.
     */
    public DnsMessage resolve(DnsMessage queryMessage) throws IOException {
        DnsMessage upstreamResponse = upstreamClient.query(queryMessage);

        // Adjust response header to reflect our server responding to client
        if (upstreamResponse != null && upstreamResponse.getHeader() != null) {
            DnsHeader header = upstreamResponse.getHeader();
            header.setId(queryMessage.getHeader().getId()); // Ensure matching transaction ID
            header.setRa(true); // Recursion Available
        }

        return upstreamResponse;
    }

    public UpstreamClient getUpstreamClient() {
        return upstreamClient;
    }
}
