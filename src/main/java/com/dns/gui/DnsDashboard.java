package com.dns.gui;

import com.dns.cache.DnsCache;
import com.dns.filter.BlockList;
import com.dns.protocol.DnsRecord;
import com.dns.protocol.RecordType;
import com.dns.server.DnsServer;
import com.dns.server.ZoneStore;
import com.dns.stats.QueryLogger;
import com.dns.stats.QueryStats;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.LineBorder;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.util.List;

/**
 * Modern Swing Dashboard for real-time DNS monitoring, statistics, and server control.
 */
public class DnsDashboard extends JFrame {

    // Dark theme color palette
    private static final Color BG_DARK = new Color(24, 25, 38);
    private static final Color BG_PANEL = new Color(33, 34, 52);
    private static final Color BG_CARD = new Color(42, 44, 68);
    private static final Color ACCENT_CYAN = new Color(0, 210, 255);
    private static final Color ACCENT_GREEN = new Color(38, 222, 129);
    private static final Color ACCENT_RED = new Color(255, 77, 109);
    private static final Color ACCENT_AMBER = new Color(254, 211, 48);
    private static final Color ACCENT_PURPLE = new Color(165, 94, 234);
    private static final Color TEXT_PRIMARY = new Color(245, 246, 250);
    private static final Color TEXT_MUTED = new Color(160, 165, 186);

    private final DnsServer server;
    private final QueryStats stats;
    private final DnsCache cache;
    private final ZoneStore zoneStore;
    private final BlockList blockList;
    private final QueryLogger queryLogger;

    // UI Widgets
    private JLabel totalQueriesLabel;
    private JLabel cacheRatioLabel;
    private JLabel blockedQueriesLabel;
    private JLabel qpmLabel;
    private JLabel upstreamQueriesLabel;

    private DefaultTableModel logTableModel;
    private DefaultTableModel topQueriedModel;
    private DefaultTableModel topBlockedModel;

    private CacheGaugePanel cacheGauge;

    public DnsDashboard(DnsServer server) {
        super("DNS Server & Resolver Dashboard");
        this.server = server;
        this.stats = server.getStats();
        this.cache = server.getCache();
        this.zoneStore = server.getZoneStore();
        this.blockList = server.getBlockList();
        this.queryLogger = server.getQueryLogger();

        initUi();
        setupListener();
        startStatsRefreshTimer();
    }

    private void initUi() {
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        setSize(1240, 780);
        setLocationRelativeTo(null);
        getContentPane().setBackground(BG_DARK);
        setLayout(new BorderLayout(10, 10));

        // Header Panel
        add(createHeaderPanel(), BorderLayout.NORTH);

        // Center Content: Cards + Tables
        JPanel centerPanel = new JPanel(new BorderLayout(10, 10));
        centerPanel.setBackground(BG_DARK);
        centerPanel.setBorder(new EmptyBorder(0, 15, 15, 15));

        // Stat metric cards
        centerPanel.add(createMetricsCardsPanel(), BorderLayout.NORTH);

        // Main Split Pane: Log Table on left/center, Insights & Charts on right
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        splitPane.setDividerLocation(780);
        splitPane.setDividerSize(4);
        splitPane.setBorder(null);
        splitPane.setBackground(BG_DARK);

        splitPane.setLeftComponent(createLiveLogPanel());
        splitPane.setRightComponent(createInsightsPanel());

        centerPanel.add(splitPane, BorderLayout.CENTER);
        add(centerPanel, BorderLayout.CENTER);
    }

    private JPanel createHeaderPanel() {
        JPanel header = new JPanel(new BorderLayout());
        header.setBackground(BG_PANEL);
        header.setBorder(new EmptyBorder(14, 20, 14, 20));

        JLabel titleLabel = new JLabel("DNS SERVER & RESOLVER MONITOR");
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 18));
        titleLabel.setForeground(TEXT_PRIMARY);

        String statusStr = "Status: LISTENING (UDP/TCP :" + server.getConfig().getServerPort() + ")  |  Zone: "
                + zoneStore.getOrigin() + "  |  Upstreams: " + server.getConfig().getUpstreamServers().size();
        JLabel statusLabel = new JLabel(statusStr);
        statusLabel.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        statusLabel.setForeground(ACCENT_GREEN);

        JPanel leftGroup = new JPanel(new GridLayout(2, 1, 2, 2));
        leftGroup.setOpaque(false);
        leftGroup.add(titleLabel);
        leftGroup.add(statusLabel);

        // Toolbar Action Buttons
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        actions.setOpaque(false);

        JButton flushCacheBtn = createStyledButton("Flush Cache", ACCENT_AMBER);
        flushCacheBtn.addActionListener(e -> {
            cache.flush();
            JOptionPane.showMessageDialog(this, "DNS Cache successfully cleared!", "Cache Flushed", JOptionPane.INFORMATION_MESSAGE);
        });

        JButton addRecordBtn = createStyledButton("+ Add Record", ACCENT_CYAN);
        addRecordBtn.addActionListener(e -> showAddRecordDialog());

        JButton reloadZoneBtn = createStyledButton("Reload Zone", BG_CARD);
        reloadZoneBtn.addActionListener(e -> {
            zoneStore.load();
            JOptionPane.showMessageDialog(this, "Zone reloaded! Total records: " + zoneStore.getTotalRecordsCount(), "Zone Reload", JOptionPane.INFORMATION_MESSAGE);
        });

        JButton reloadBlockBtn = createStyledButton("Reload Blocklist", BG_CARD);
        reloadBlockBtn.addActionListener(e -> {
            blockList.load();
            JOptionPane.showMessageDialog(this, "Blocklist reloaded! Rules active: " + blockList.getBlockedCount(), "Blocklist Reload", JOptionPane.INFORMATION_MESSAGE);
        });

        actions.add(flushCacheBtn);
        actions.add(addRecordBtn);
        actions.add(reloadZoneBtn);
        actions.add(reloadBlockBtn);

        header.add(leftGroup, BorderLayout.WEST);
        header.add(actions, BorderLayout.EAST);
        return header;
    }

    private JPanel createMetricsCardsPanel() {
        JPanel panel = new JPanel(new GridLayout(1, 5, 12, 12));
        panel.setBackground(BG_DARK);
        panel.setBorder(new EmptyBorder(10, 0, 10, 0));

        totalQueriesLabel = new JLabel("0");
        cacheRatioLabel = new JLabel("0.0%");
        blockedQueriesLabel = new JLabel("0");
        qpmLabel = new JLabel("0");
        upstreamQueriesLabel = new JLabel("0");

        panel.add(createCard("TOTAL QUERIES", totalQueriesLabel, ACCENT_CYAN));
        panel.add(createCard("CACHE HIT RATIO", cacheRatioLabel, ACCENT_GREEN));
        panel.add(createCard("BLOCKED AD/MALWARE", blockedQueriesLabel, ACCENT_RED));
        panel.add(createCard("QUERIES / MINUTE", qpmLabel, ACCENT_PURPLE));
        panel.add(createCard("UPSTREAM QUERIES", upstreamQueriesLabel, ACCENT_AMBER));

        return panel;
    }

    private JPanel createCard(String title, JLabel valueLabel, Color accentColor) {
        JPanel card = new JPanel(new BorderLayout(5, 5));
        card.setBackground(BG_CARD);
        card.setBorder(BorderFactory.createCompoundBorder(
                new LineBorder(new Color(60, 63, 95), 1, true),
                new EmptyBorder(12, 15, 12, 15)
        ));

        JLabel titleLbl = new JLabel(title);
        titleLbl.setFont(new Font("Segoe UI", Font.BOLD, 10));
        titleLbl.setForeground(TEXT_MUTED);

        valueLabel.setFont(new Font("Segoe UI", Font.BOLD, 22));
        valueLabel.setForeground(accentColor);

        card.add(titleLbl, BorderLayout.NORTH);
        card.add(valueLabel, BorderLayout.CENTER);
        return card;
    }

    private JPanel createLiveLogPanel() {
        JPanel panel = new JPanel(new BorderLayout(0, 8));
        panel.setBackground(BG_PANEL);
        panel.setBorder(BorderFactory.createCompoundBorder(
                new LineBorder(new Color(50, 52, 80), 1, true),
                new EmptyBorder(10, 12, 10, 12)
        ));

        JLabel header = new JLabel("Live DNS Query Log");
        header.setFont(new Font("Segoe UI", Font.BOLD, 14));
        header.setForeground(TEXT_PRIMARY);
        panel.add(header, BorderLayout.NORTH);

        String[] cols = {"Time", "Client IP", "Domain", "Type", "Status", "Source", "Latency"};
        logTableModel = new DefaultTableModel(cols, 0) {
            @Override
            public boolean isCellEditable(int row, int col) { return false; }
        };

        JTable table = new JTable(logTableModel);
        table.setBackground(BG_PANEL);
        table.setForeground(TEXT_PRIMARY);
        table.setFont(new Font("Consolas", Font.PLAIN, 12));
        table.setRowHeight(24);
        table.setShowGrid(false);
        table.setSelectionBackground(new Color(55, 58, 88));

        table.getTableHeader().setBackground(BG_CARD);
        table.getTableHeader().setForeground(TEXT_MUTED);
        table.getTableHeader().setFont(new Font("Segoe UI", Font.BOLD, 11));

        // Center / style renderers
        table.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable t, Object val, boolean isSel, boolean hasFocus, int row, int col) {
                Component c = super.getTableCellRendererComponent(t, val, isSel, hasFocus, row, col);
                setBackground(isSel ? new Color(55, 58, 88) : BG_PANEL);

                String text = val != null ? val.toString() : "";
                if (col == 4) { // Status
                    if ("NOERROR".equals(text)) setForeground(ACCENT_GREEN);
                    else if ("NXDOMAIN".equals(text)) setForeground(ACCENT_AMBER);
                    else setForeground(ACCENT_RED);
                } else if (col == 5) { // Source
                    if ("ZONE".equals(text)) setForeground(ACCENT_CYAN);
                    else if ("CACHE".equals(text)) setForeground(ACCENT_GREEN);
                    else if ("UPSTREAM".equals(text)) setForeground(ACCENT_PURPLE);
                    else if ("BLOCKED".equals(text)) setForeground(ACCENT_RED);
                    else setForeground(TEXT_PRIMARY);
                } else {
                    setForeground(TEXT_PRIMARY);
                }
                return c;
            }
        });

        table.getColumnModel().getColumn(0).setPreferredWidth(85);
        table.getColumnModel().getColumn(1).setPreferredWidth(100);
        table.getColumnModel().getColumn(2).setPreferredWidth(210);
        table.getColumnModel().getColumn(3).setPreferredWidth(50);
        table.getColumnModel().getColumn(4).setPreferredWidth(80);
        table.getColumnModel().getColumn(5).setPreferredWidth(80);
        table.getColumnModel().getColumn(6).setPreferredWidth(65);

        JScrollPane scrollPane = new JScrollPane(table);
        scrollPane.getViewport().setBackground(BG_PANEL);
        scrollPane.setBorder(null);

        panel.add(scrollPane, BorderLayout.CENTER);
        return panel;
    }

    private JPanel createInsightsPanel() {
        JPanel panel = new JPanel(new GridLayout(3, 1, 0, 10));
        panel.setBackground(BG_DARK);

        // 1. Cache Performance Gauge Card
        JPanel gaugeCard = new JPanel(new BorderLayout(5, 5));
        gaugeCard.setBackground(BG_PANEL);
        gaugeCard.setBorder(BorderFactory.createCompoundBorder(
                new LineBorder(new Color(50, 52, 80), 1, true),
                new EmptyBorder(10, 12, 10, 12)
        ));
        JLabel gaugeHeader = new JLabel("Cache Efficiency");
        gaugeHeader.setFont(new Font("Segoe UI", Font.BOLD, 13));
        gaugeHeader.setForeground(TEXT_PRIMARY);
        gaugeCard.add(gaugeHeader, BorderLayout.NORTH);

        cacheGauge = new CacheGaugePanel();
        gaugeCard.add(cacheGauge, BorderLayout.CENTER);
        panel.add(gaugeCard);

        // 2. Top Queried Domains Card
        JPanel topQueriedCard = createMiniTableCard("Top Queried Domains", topQueriedModel = new DefaultTableModel(new String[]{"Domain", "Hits"}, 0));
        panel.add(topQueriedCard);

        // 3. Top Blocked Domains Card
        JPanel topBlockedCard = createMiniTableCard("Top Blocked Domains", topBlockedModel = new DefaultTableModel(new String[]{"Blocked Domain", "Blocked"}, 0));
        panel.add(topBlockedCard);

        return panel;
    }

    private JPanel createMiniTableCard(String title, DefaultTableModel model) {
        JPanel card = new JPanel(new BorderLayout(0, 6));
        card.setBackground(BG_PANEL);
        card.setBorder(BorderFactory.createCompoundBorder(
                new LineBorder(new Color(50, 52, 80), 1, true),
                new EmptyBorder(8, 10, 8, 10)
        ));

        JLabel header = new JLabel(title);
        header.setFont(new Font("Segoe UI", Font.BOLD, 12));
        header.setForeground(TEXT_PRIMARY);
        card.add(header, BorderLayout.NORTH);

        JTable table = new JTable(model);
        table.setBackground(BG_PANEL);
        table.setForeground(TEXT_PRIMARY);
        table.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        table.setRowHeight(20);
        table.setShowGrid(false);
        table.getTableHeader().setBackground(BG_CARD);
        table.getTableHeader().setForeground(TEXT_MUTED);
        table.getColumnModel().getColumn(0).setPreferredWidth(160);
        table.getColumnModel().getColumn(1).setPreferredWidth(45);

        JScrollPane sp = new JScrollPane(table);
        sp.getViewport().setBackground(BG_PANEL);
        sp.setBorder(null);
        card.add(sp, BorderLayout.CENTER);
        return card;
    }

    private JButton createStyledButton(String text, Color accent) {
        JButton btn = new JButton(text);
        btn.setFont(new Font("Segoe UI", Font.BOLD, 12));
        btn.setForeground(Color.WHITE);
        btn.setBackground(accent.darker());
        btn.setFocusPainted(false);
        btn.setBorder(BorderFactory.createCompoundBorder(
                new LineBorder(accent, 1, true),
                new EmptyBorder(6, 12, 6, 12)
        ));
        btn.setCursor(new Cursor(Cursor.HAND_CURSOR));
        return btn;
    }

    private void showAddRecordDialog() {
        JDialog dialog = new JDialog(this, "Add Local DNS Record", true);
        dialog.setSize(380, 290);
        dialog.setLocationRelativeTo(this);
        dialog.getContentPane().setBackground(BG_PANEL);
        dialog.setLayout(new GridLayout(5, 2, 10, 10));
        ((JPanel) dialog.getContentPane()).setBorder(new EmptyBorder(20, 20, 20, 20));

        JTextField nameField = new JTextField("test.mycompany.local");
        JComboBox<RecordType> typeCombo = new JComboBox<>(new RecordType[]{
                RecordType.A, RecordType.AAAA, RecordType.CNAME, RecordType.TXT, RecordType.MX
        });
        JTextField ttlField = new JTextField("3600");
        JTextField valField = new JTextField("192.168.1.99");

        dialog.add(createDialogLabel("Domain Name:"));
        dialog.add(nameField);
        dialog.add(createDialogLabel("Record Type:"));
        dialog.add(typeCombo);
        dialog.add(createDialogLabel("TTL (seconds):"));
        dialog.add(ttlField);
        dialog.add(createDialogLabel("Target / Value:"));
        dialog.add(valField);

        JButton saveBtn = createStyledButton("Save Record", ACCENT_GREEN);
        saveBtn.addActionListener(e -> {
            try {
                String name = nameField.getText().trim();
                RecordType type = (RecordType) typeCombo.getSelectedItem();
                long ttl = Long.parseLong(ttlField.getText().trim());
                String val = valField.getText().trim();

                DnsRecord rec = switch (type) {
                    case A -> DnsRecord.createA(name, ttl, val);
                    case AAAA -> DnsRecord.createAAAA(name, ttl, val);
                    case CNAME -> DnsRecord.createCNAME(name, ttl, val);
                    case TXT -> DnsRecord.createTXT(name, ttl, val);
                    case MX -> DnsRecord.createMX(name, ttl, 10, val);
                    default -> null;
                };

                if (rec != null) {
                    zoneStore.addRecord(rec);
                    JOptionPane.showMessageDialog(dialog, "Record successfully added to local zone!", "Success", JOptionPane.INFORMATION_MESSAGE);
                    dialog.dispose();
                }
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(dialog, "Error: " + ex.getMessage(), "Input Error", JOptionPane.ERROR_MESSAGE);
            }
        });

        JButton cancelBtn = createStyledButton("Cancel", BG_CARD);
        cancelBtn.addActionListener(e -> dialog.dispose());

        dialog.add(saveBtn);
        dialog.add(cancelBtn);
        dialog.setVisible(true);
    }

    private JLabel createDialogLabel(String text) {
        JLabel lbl = new JLabel(text);
        lbl.setForeground(TEXT_PRIMARY);
        lbl.setFont(new Font("Segoe UI", Font.BOLD, 12));
        return lbl;
    }

    private void setupListener() {
        queryLogger.addListener(entry -> SwingUtilities.invokeLater(() -> {
            if (logTableModel.getRowCount() >= 1000) {
                logTableModel.removeRow(logTableModel.getRowCount() - 1);
            }
            logTableModel.insertRow(0, new Object[]{
                    entry.getFormattedTime(),
                    entry.getClientIp(),
                    entry.getDomain(),
                    entry.getRecordType(),
                    entry.getRcode(),
                    entry.getSource(),
                    entry.getLatencyMs() + "ms"
            });
        }));
    }

    private void startStatsRefreshTimer() {
        Timer timer = new Timer(1000, (ActionEvent e) -> updateStatsUi());
        timer.start();
    }

    private void updateStatsUi() {
        totalQueriesLabel.setText(String.format("%,d", stats.getTotalQueries()));
        double ratio = stats.getCacheHitRatio() * 100.0;
        cacheRatioLabel.setText(String.format("%.1f%%", ratio));
        blockedQueriesLabel.setText(String.format("%,d", stats.getBlockedQueries()));
        qpmLabel.setText(String.valueOf(stats.getQueriesPerMinute()));
        upstreamQueriesLabel.setText(String.format("%,d", stats.getUpstreamQueries()));

        cacheGauge.setRatio(ratio);

        // Update Top Queried
        List<QueryStats.DomainCount> topQ = stats.getTopQueried(5);
        topQueriedModel.setRowCount(0);
        for (QueryStats.DomainCount dc : topQ) {
            topQueriedModel.addRow(new Object[]{dc.getDomain(), dc.getCount()});
        }

        // Update Top Blocked
        List<QueryStats.DomainCount> topB = stats.getTopBlocked(5);
        topBlockedModel.setRowCount(0);
        for (QueryStats.DomainCount dc : topB) {
            topBlockedModel.addRow(new Object[]{dc.getDomain(), dc.getCount()});
        }
    }

    /**
     * Sleek custom-painted circular gauge for Cache Hit Ratio.
     */
    private static class CacheGaugePanel extends JPanel {
        private double ratio = 0.0;

        public CacheGaugePanel() {
            setOpaque(false);
        }

        public void setRatio(double ratio) {
            this.ratio = Math.max(0.0, Math.min(100.0, ratio));
            repaint();
        }

        @Override
        protected void paintComponent(Graphics g) {
            super.paintComponent(g);
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

            int width = getWidth();
            int height = getHeight();
            int size = Math.min(width, height) - 24;
            int x = (width - size) / 2;
            int y = (height - size) / 2;

            // Background circle track
            g2.setStroke(new BasicStroke(10f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
            g2.setColor(new Color(55, 58, 88));
            g2.drawArc(x, y, size, size, -90, 360);

            // Active hit ratio arc
            int sweepAngle = (int) Math.round((ratio / 100.0) * 360.0);
            if (sweepAngle > 0) {
                g2.setPaint(new GradientPaint(x, y, ACCENT_GREEN, x + size, y + size, ACCENT_CYAN));
                g2.drawArc(x, y, size, size, 90, -sweepAngle);
            }

            // Percentage label in center
            g2.setColor(TEXT_PRIMARY);
            g2.setFont(new Font("Segoe UI", Font.BOLD, 18));
            String text = String.format("%.1f%%", ratio);
            FontMetrics fm = g2.getFontMetrics();
            int textX = (width - fm.stringWidth(text)) / 2;
            int textY = (height + fm.getAscent() / 2) / 2 - 2;
            g2.drawString(text, textX, textY);

            g2.dispose();
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            DnsServer s = new DnsServer();
            try {
                s.start();
                DnsDashboard d = new DnsDashboard(s);
                d.setVisible(true);
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
    }
}
