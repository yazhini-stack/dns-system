package com.dns.client;

import com.dns.protocol.DnsCodec;
import com.dns.protocol.DnsMessage;
import com.dns.protocol.RecordType;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.Random;

/**
 * Command-line DNS query tool mimicking the standard Unix 'dig' command.
 * Usage:
 *   java com.dns.client.DigClient [@server] [-p port] <domain> [type] [+tcp]
 */
public class DigClient {

    private static final Random RANDOM = new Random();

    public static class DigOptions {
        public String server = "127.0.0.1";
        public int port = 5353;
        public String domain = "mycompany.local";
        public RecordType type = RecordType.A;
        public boolean tcp = false;
        public int timeoutMs = 3000;
    }

    public static DigOptions parseArgs(String[] args) {
        DigOptions opts = new DigOptions();
        for (int i = 0; i < args.length; i++) {
            String arg = args[i].trim();
            if (arg.startsWith("@")) {
                opts.server = arg.substring(1);
            } else if (arg.equals("-p") && i + 1 < args.length) {
                opts.port = Integer.parseInt(args[++i]);
            } else if (arg.equalsIgnoreCase("+tcp")) {
                opts.tcp = true;
            } else if (arg.startsWith("+timeout=")) {
                opts.timeoutMs = Integer.parseInt(arg.substring("+timeout=".length())) * 1000;
            } else {
                RecordType detectedType = RecordType.fromName(arg);
                if (detectedType != RecordType.UNKNOWN) {
                    opts.type = detectedType;
                } else {
                    opts.domain = arg;
                }
            }
        }
        return opts;
    }

    public static DnsMessage query(DigOptions opts) throws IOException {
        int txId = RANDOM.nextInt(0xFFFF);
        DnsMessage queryMessage = DnsMessage.createQuery(txId, opts.domain, opts.type, true);
        byte[] wireQuery = DnsCodec.encode(queryMessage);

        long start = System.currentTimeMillis();
        byte[] responseBytes;

        if (opts.tcp) {
            responseBytes = queryTcp(opts.server, opts.port, wireQuery, opts.timeoutMs);
        } else {
            responseBytes = queryUdp(opts.server, opts.port, wireQuery, opts.timeoutMs);
        }

        long elapsedMs = System.currentTimeMillis() - start;
        DnsMessage response = DnsCodec.decode(responseBytes);

        // Check if UDP was truncated and retry TCP automatically
        if (!opts.tcp && response.getHeader().isTc()) {
            System.out.println(";; Truncated response received over UDP, retrying via TCP...");
            start = System.currentTimeMillis();
            responseBytes = queryTcp(opts.server, opts.port, wireQuery, opts.timeoutMs);
            elapsedMs = System.currentTimeMillis() - start;
            response = DnsCodec.decode(responseBytes);
        }

        String serverTag = opts.server + "#" + opts.port + "(" + opts.server + ")";
        System.out.print(response.toDigOutput(elapsedMs, serverTag, responseBytes.length));
        return response;
    }

    private static byte[] queryUdp(String host, int port, byte[] wireQuery, int timeoutMs) throws IOException {
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(timeoutMs);
            InetAddress address = InetAddress.getByName(host);
            DatagramPacket sendPacket = new DatagramPacket(wireQuery, wireQuery.length, address, port);
            socket.send(sendPacket);

            byte[] buffer = new byte[4096];
            DatagramPacket recvPacket = new DatagramPacket(buffer, buffer.length);
            socket.receive(recvPacket);

            byte[] result = new byte[recvPacket.getLength()];
            System.arraycopy(recvPacket.getData(), recvPacket.getOffset(), result, 0, recvPacket.getLength());
            return result;
        }
    }

    private static byte[] queryTcp(String host, int port, byte[] wireQuery, int timeoutMs) throws IOException {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), timeoutMs);
            socket.setSoTimeout(timeoutMs);

            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            DataInputStream in = new DataInputStream(socket.getInputStream());

            out.writeShort(wireQuery.length);
            out.write(wireQuery);
            out.flush();

            int length = in.readUnsignedShort();
            byte[] responseBytes = new byte[length];
            in.readFully(responseBytes);
            return responseBytes;
        }
    }

    public static void main(String[] args) {
        if (args.length == 0 || args[0].equals("-h") || args[0].equals("--help")) {
            System.out.println("Usage: java com.dns.client.DigClient [@server] [-p port] <domain> [type] [+tcp]");
            System.out.println("Examples:");
            System.out.println("  DigClient @127.0.0.1 -p 5353 www.mycompany.local A");
            System.out.println("  DigClient @127.0.0.1 -p 5353 google.com A");
            System.out.println("  DigClient @8.8.8.8 -p 53 example.com AAAA +tcp");
            return;
        }

        try {
            DigOptions opts = parseArgs(args);
            query(opts);
        } catch (Exception e) {
            System.err.println(";; Connection to " + args[0] + " failed: " + e.getMessage());
            System.exit(1);
        }
    }
}
