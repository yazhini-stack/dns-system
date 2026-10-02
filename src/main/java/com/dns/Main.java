package com.dns;

import com.dns.client.DigClient;
import com.dns.gui.DnsDashboard;
import com.dns.server.DnsServer;

import java.util.Arrays;

/**
 * Unified application launcher for DNS Server, Dig Client, and GUI Dashboard.
 */
public class Main {

    public static void main(String[] args) {
        if (args.length > 0 && args[0].equalsIgnoreCase("dig")) {
            String[] digArgs = Arrays.copyOfRange(args, 1, args.length);
            DigClient.main(digArgs);
            return;
        }

        if (args.length > 0 && (args[0].equalsIgnoreCase("gui") || args[0].equalsIgnoreCase("--gui"))) {
            DnsDashboard.main(args);
            return;
        }

        // Default: Start DNS Server
        DnsServer.main(args);
    }
}
