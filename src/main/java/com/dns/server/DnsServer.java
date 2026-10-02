package com.dns.server;

import com.dns.cache.DnsCache;
import com.dns.filter.BlockList;
import com.dns.protocol.DnsCodec;
import com.dns.protocol.DnsMessage;
import com.dns.resolver.RecursiveResolver;
import com.dns.stats.QueryLogger;
import com.dns.stats.QueryStats;
import com.dns.util.ConfigLoader;
import com.dns.util.Logger;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.BindException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Main DNS Server engine listening on UDP and TCP (default port 5353).
 * Multithreaded, resilient to malformed packets, socket timeouts, and port conflicts.
 */
public class DnsServer {

    private final ConfigLoader config;
    private final ZoneStore zoneStore;
    private final BlockList blockList;
    private final DnsCache cache;
    private final RecursiveResolver recursiveResolver;
    private final QueryStats stats;
    private final QueryLogger queryLogger;
    private final QueryHandler queryHandler;

    private DatagramSocket udpSocket;
    private ServerSocket tcpServerSocket;
    private ExecutorService workerPool;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private int boundPort = 5353;
    private WebDashboardServer webDashboard;

    public DnsServer() {
        this(new ConfigLoader());
    }

    public DnsServer(ConfigLoader config) {
        this.config = config;
        this.zoneStore = new ZoneStore(config.getZonePath());
        this.blockList = new BlockList(config.getBlocklistPath());
        this.cache = new DnsCache(config.getCacheMaxSize(), config.getNegativeTtlSeconds());
        this.recursiveResolver = new RecursiveResolver(config.getUpstreamServers(), config.getUpstreamTimeoutMs());
        this.stats = new QueryStats();
        this.queryLogger = new QueryLogger(config.getLogFilePath());
        this.queryHandler = new QueryHandler(config, zoneStore, blockList, cache, recursiveResolver, stats, queryLogger);
    }

    public synchronized void start() throws IOException {
        if (running.get()) {
            Logger.warn("DNS Server is already running.");
            return;
        }

        int targetPort = config.getServerPort();
        int actualPort = targetPort;
        String host = config.getServerHost();
        InetAddress bindAddress = InetAddress.getByName(host);

        // 1. Initialize UDP socket with exclusive bind and automatic port-in-use fallback
        udpSocket = new DatagramSocket(null);
        boolean bound = false;
        int maxAttempts = 10;
        for (int attempt = 0; attempt < maxAttempts; attempt++) {
            int portToTry = targetPort + attempt;
            try {
                udpSocket.bind(new InetSocketAddress(bindAddress, portToTry));
                actualPort = portToTry;
                bound = true;
                if (attempt > 0) {
                    Logger.warn("Requested port " + targetPort + " was in use by another process. Successfully bound to fallback port " + actualPort);
                }
                break;
            } catch (BindException e) {
                Logger.warn("Port " + portToTry + " is in use. Trying next available port...");
            }
        }

        if (!bound) {
            throw new BindException("Failed to bind UDP port " + targetPort + " after " + maxAttempts + " attempts.");
        }
        this.boundPort = actualPort;

        // 2. Initialize TCP socket (if enabled)
        if (config.isTcpEnabled()) {
            try {
                tcpServerSocket = new ServerSocket();
                tcpServerSocket.setReuseAddress(true);
                tcpServerSocket.bind(new InetSocketAddress(bindAddress, actualPort));
            } catch (BindException e) {
                Logger.warn("TCP port " + actualPort + " could not be bound (" + e.getMessage() + "). Continuing with UDP only.");
            }
        }

        int poolSize = config.getThreadPoolSize();
        workerPool = Executors.newFixedThreadPool(poolSize, r -> {
            Thread t = new Thread(r, "dns-worker");
            t.setDaemon(true);
            return t;
        });

        running.set(true);

        // Start UDP listener thread
        Thread udpListenerThread = new Thread(this::listenUdp, "dns-udp-listener");
        udpListenerThread.start();

        // Start TCP listener thread if TCP socket is active
        if (tcpServerSocket != null && !tcpServerSocket.isClosed()) {
            Thread tcpListenerThread = new Thread(this::listenTcp, "dns-tcp-listener");
            tcpListenerThread.start();
        }

        // Start built-in Web Dashboard HTTP server
        try {
            webDashboard = new WebDashboardServer(this, 5380);
            webDashboard.start();
        } catch (Exception e) {
            Logger.warn("Could not start Web Dashboard on port 5380: " + e.getMessage());
        }

        Logger.info("===============================================================================");
        Logger.info("  DNS Server and Resolver started successfully!");
        Logger.info("  Listening on UDP/TCP: " + bindAddress.getHostAddress() + ":" + actualPort);
        Logger.info("  Web Dashboard Link  : http://localhost:5380");
        Logger.info("  Authoritative Zone : " + zoneStore.getOrigin() + " (" + zoneStore.getTotalRecordsCount() + " records)");
        Logger.info("  Blocklist Rules    : " + blockList.getBlockedCount() + " rules loaded");
        Logger.info("  Upstream Servers   : " + config.getUpstreamServers());
        Logger.info("  Worker Thread Pool : " + poolSize + " threads");
        Logger.info("===============================================================================");

        Runtime.getRuntime().addShutdownHook(new Thread(this::stop, "dns-shutdown-hook"));
    }

    private void listenUdp() {
        byte[] buffer = new byte[DnsCodec.MAX_UDP_PAYLOAD_SIZE * 8]; // Support EDNS0 buffers
        while (running.get() && !udpSocket.isClosed()) {
            try {
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                udpSocket.receive(packet);

                // Copy received data to preserve buffer integrity across threads
                byte[] queryData = new byte[packet.getLength()];
                System.arraycopy(packet.getData(), packet.getOffset(), queryData, 0, packet.getLength());
                InetAddress clientAddr = packet.getAddress();
                int clientPort = packet.getPort();

                workerPool.submit(() -> processUdpQuery(queryData, clientAddr, clientPort));
            } catch (IOException e) {
                if (running.get()) {
                    Logger.error("UDP socket receive error: " + e.getMessage());
                }
            }
        }
    }

    private void processUdpQuery(byte[] queryData, InetAddress clientAddr, int clientPort) {
        try {
            DnsMessage query = DnsCodec.decode(queryData);
            DnsMessage response = queryHandler.handleQuery(query, clientAddr);

            byte[] responseBytes = DnsCodec.encode(response);

            // Handle UDP truncation (RFC 1035 Section 4.2.1):
            // If response exceeds 512 bytes, truncate and set TC bit so client falls back to TCP
            if (responseBytes.length > DnsCodec.MAX_UDP_PAYLOAD_SIZE) {
                Logger.info("Response exceeds 512 bytes (" + responseBytes.length + " bytes). Setting TC=1.");
                response.getHeader().setTc(true);
                responseBytes = DnsCodec.encode(response);
            }

            DatagramPacket respPacket = new DatagramPacket(responseBytes, responseBytes.length, clientAddr, clientPort);
            udpSocket.send(respPacket);
        } catch (DnsCodec.DnsParseException e) {
            Logger.warn("Malformed DNS packet from " + clientAddr + ": " + e.getMessage());
        } catch (Exception e) {
            Logger.error("Error processing query from " + clientAddr + ": " + e.getMessage(), e);
        }
    }

    private void listenTcp() {
        while (running.get() && tcpServerSocket != null && !tcpServerSocket.isClosed()) {
            try {
                Socket socket = tcpServerSocket.accept();
                workerPool.submit(() -> processTcpConnection(socket));
            } catch (IOException e) {
                if (running.get()) {
                    Logger.error("TCP server socket accept error: " + e.getMessage());
                }
            }
        }
    }

    private void processTcpConnection(Socket socket) {
        try (socket) {
            socket.setSoTimeout(5000);
            DataInputStream in = new DataInputStream(socket.getInputStream());
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());

            int length = in.readUnsignedShort();
            byte[] queryBytes = new byte[length];
            in.readFully(queryBytes);

            DnsMessage query = DnsCodec.decode(queryBytes);
            DnsMessage response = queryHandler.handleQuery(query, socket.getInetAddress());

            byte[] responseBytes = DnsCodec.encode(response);
            out.writeShort(responseBytes.length);
            out.write(responseBytes);
            out.flush();
        } catch (Exception e) {
            Logger.warn("TCP connection handling error from " + socket.getRemoteSocketAddress() + ": " + e.getMessage());
        }
    }

    public synchronized void stop() {
        if (!running.get()) return;
        running.set(false);
        Logger.info("Stopping DNS Server...");

        if (udpSocket != null && !udpSocket.isClosed()) {
            udpSocket.close();
        }
        if (tcpServerSocket != null && !tcpServerSocket.isClosed()) {
            try {
                tcpServerSocket.close();
            } catch (IOException ignored) {}
        }
        if (workerPool != null) {
            workerPool.shutdown();
            try {
                if (!workerPool.awaitTermination(3, TimeUnit.SECONDS)) {
                    workerPool.shutdownNow();
                }
            } catch (InterruptedException e) {
                workerPool.shutdownNow();
            }
        }
        if (webDashboard != null) {
            webDashboard.stop();
        }
        Logger.info("DNS Server stopped.");
    }

    public boolean isRunning() { return running.get(); }
    public int getBoundPort() { return boundPort; }
    public QueryHandler getQueryHandler() { return queryHandler; }
    public ZoneStore getZoneStore() { return zoneStore; }
    public BlockList getBlockList() { return blockList; }
    public DnsCache getCache() { return cache; }
    public QueryStats getStats() { return stats; }
    public QueryLogger getQueryLogger() { return queryLogger; }
    public ConfigLoader getConfig() { return config; }

    public static void main(String[] args) {
        String configPath = "config/dns.properties";
        boolean openGui = false;
        Integer customPort = null;

        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if (arg.startsWith("--config=")) {
                configPath = arg.substring("--config=".length());
            } else if (arg.startsWith("--port=")) {
                customPort = Integer.parseInt(arg.substring("--port=".length()));
            } else if (arg.equals("-p") && i + 1 < args.length) {
                customPort = Integer.parseInt(args[++i]);
            } else if (arg.equals("--gui") || arg.equals("-g")) {
                openGui = true;
            }
        }

        ConfigLoader configLoader = new ConfigLoader(configPath);
        if (customPort != null) {
            configLoader.setServerPort(customPort);
        }
        DnsServer server = new DnsServer(configLoader);

        try {
            server.start();

            if (openGui) {
                javax.swing.SwingUtilities.invokeLater(() -> {
                    try {
                        com.dns.gui.DnsDashboard dashboard = new com.dns.gui.DnsDashboard(server);
                        dashboard.setVisible(true);
                    } catch (Exception e) {
                        Logger.error("Failed to launch GUI dashboard: " + e.getMessage(), e);
                    }
                });
            }

            // Keep main thread alive
            while (server.isRunning()) {
                Thread.sleep(1000);
            }
        } catch (Exception e) {
            Logger.error("DNS Server fatal startup error: " + e.getMessage(), e);
            System.exit(1);
        }
    }
}
