package com.dns.resolver;

import com.dns.protocol.DnsCodec;
import com.dns.protocol.DnsMessage;
import com.dns.util.Logger;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.List;

/**
 * Handles communication with upstream DNS servers over UDP, with automatic TCP fallback
 * when responses have the truncation flag (TC) set.
 */
public class UpstreamClient {

    public static class ServerEndpoint {
        private final String host;
        private final int port;

        public ServerEndpoint(String host, int port) {
            this.host = host;
            this.port = port;
        }

        public static ServerEndpoint parse(String endpointStr) {
            String[] parts = endpointStr.trim().split(":");
            String host = parts[0];
            int port = 53;
            if (parts.length > 1) {
                try {
                    port = Integer.parseInt(parts[1]);
                } catch (NumberFormatException ignored) {}
            }
            return new ServerEndpoint(host, port);
        }

        public String getHost() { return host; }
        public int getPort() { return port; }

        @Override
        public String toString() {
            return host + ":" + port;
        }
    }

    private final List<ServerEndpoint> upstreamServers = new ArrayList<>();
    private final int timeoutMs;

    public UpstreamClient(List<String> servers, int timeoutMs) {
        this.timeoutMs = timeoutMs > 0 ? timeoutMs : 2000;
        if (servers != null) {
            for (String s : servers) {
                upstreamServers.add(ServerEndpoint.parse(s));
            }
        }
        if (upstreamServers.isEmpty()) {
            upstreamServers.add(new ServerEndpoint("8.8.8.8", 53));
            upstreamServers.add(new ServerEndpoint("1.1.1.1", 53));
        }
    }

    /**
     * Resolves a DNS query using configured upstream servers with timeout and fallback.
     */
    public DnsMessage query(DnsMessage queryMessage) throws IOException {
        byte[] wireQuery = DnsCodec.encode(queryMessage);
        Exception lastException = null;

        for (ServerEndpoint server : upstreamServers) {
            try {
                DnsMessage response = queryServer(server, wireQuery);
                if (response != null) {
                    return response;
                }
            } catch (SocketTimeoutException e) {
                Logger.warn("Upstream " + server + " timed out after " + timeoutMs + "ms. Trying fallback...");
                lastException = e;
            } catch (Exception e) {
                Logger.warn("Upstream " + server + " error: " + e.getMessage() + ". Trying fallback...");
                lastException = e;
            }
        }

        if (lastException instanceof IOException ioException) {
            throw ioException;
        }
        throw new IOException("All upstream DNS servers failed", lastException);
    }

    /**
     * Sends a query to a specific upstream server via UDP, falling back to TCP if truncated (TC bit).
     */
    public DnsMessage queryServer(ServerEndpoint server, byte[] wireQuery) throws IOException {
        // 1. Try UDP first
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(timeoutMs);
            InetAddress address = InetAddress.getByName(server.getHost());
            DatagramPacket sendPacket = new DatagramPacket(wireQuery, wireQuery.length, address, server.getPort());
            socket.send(sendPacket);

            byte[] recvBuf = new byte[DnsCodec.MAX_UDP_PAYLOAD_SIZE * 8]; // Support EDNS0 buffer up to 4096
            DatagramPacket recvPacket = new DatagramPacket(recvBuf, recvBuf.length);
            socket.receive(recvPacket);

            DnsMessage response = DnsCodec.decode(recvBuf, 0, recvPacket.getLength());

            // Check if response is truncated (TC = 1) -> Fallback to TCP (RFC 1035 Section 4.2.2)
            if (response.getHeader().isTc()) {
                Logger.info("Response from " + server + " truncated (TC=1). Retrying via TCP...");
                return queryTcp(server, wireQuery);
            }

            return response;
        }
    }

    /**
     * Sends a DNS query over TCP with 2-byte prefix length (RFC 1035 Section 4.2.2).
     */
    public DnsMessage queryTcp(ServerEndpoint server, byte[] wireQuery) throws IOException {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(server.getHost(), server.getPort()), timeoutMs);
            socket.setSoTimeout(timeoutMs);

            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            DataInputStream in = new DataInputStream(socket.getInputStream());

            // Write 2-byte length prefix + wire message
            out.writeShort(wireQuery.length);
            out.write(wireQuery);
            out.flush();

            // Read 2-byte length prefix
            int respLength = in.readUnsignedShort();
            byte[] respBytes = new byte[respLength];
            in.readFully(respBytes);

            return DnsCodec.decode(respBytes);
        }
    }

    public List<ServerEndpoint> getUpstreamServers() {
        return List.copyOf(upstreamServers);
    }
}
