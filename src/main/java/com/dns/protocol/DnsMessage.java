package com.dns.protocol;

import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Represents a complete DNS message containing Header, Questions, Answers,
 * Authority records, and Additional records (RFC 1035 Section 4).
 */
public class DnsMessage {

    private DnsHeader header;
    private final List<DnsQuestion> questions;
    private final List<DnsRecord> answers;
    private final List<DnsRecord> authorities;
    private final List<DnsRecord> additionals;

    public DnsMessage() {
        this(new DnsHeader());
    }

    public DnsMessage(DnsHeader header) {
        this.header = header != null ? header : new DnsHeader();
        this.questions = new ArrayList<>();
        this.answers = new ArrayList<>();
        this.authorities = new ArrayList<>();
        this.additionals = new ArrayList<>();
    }

    public DnsHeader getHeader() {
        return header;
    }

    public void setHeader(DnsHeader header) {
        this.header = header;
    }

    public List<DnsQuestion> getQuestions() {
        return Collections.unmodifiableList(questions);
    }

    public List<DnsRecord> getAnswers() {
        return Collections.unmodifiableList(answers);
    }

    public List<DnsRecord> getAuthorities() {
        return Collections.unmodifiableList(authorities);
    }

    public List<DnsRecord> getAdditionals() {
        return Collections.unmodifiableList(additionals);
    }

    public void addQuestion(DnsQuestion question) {
        if (question != null) {
            questions.add(question);
            header.setQdCount(questions.size());
        }
    }

    public void addAnswer(DnsRecord record) {
        if (record != null) {
            answers.add(record);
            header.setAnCount(answers.size());
        }
    }

    public void addAuthority(DnsRecord record) {
        if (record != null) {
            authorities.add(record);
            header.setNsCount(authorities.size());
        }
    }

    public void addAdditional(DnsRecord record) {
        if (record != null) {
            additionals.add(record);
            header.setArCount(additionals.size());
        }
    }

    /**
     * Creates a standard query message for a domain and record type.
     */
    public static DnsMessage createQuery(int id, String domain, RecordType type, boolean recursionDesired) {
        DnsHeader header = new DnsHeader(id);
        header.setQr(false);
        header.setOpcode(DnsHeader.OPCODE_QUERY);
        header.setRd(recursionDesired);
        DnsMessage msg = new DnsMessage(header);
        msg.addQuestion(new DnsQuestion(domain, type));
        return msg;
    }

    /**
     * Initializes a response message template from a received query.
     */
    public static DnsMessage createResponse(DnsMessage query, int rcode) {
        DnsMessage response = new DnsMessage();
        DnsHeader respHeader = response.getHeader();
        if (query != null && query.getHeader() != null) {
            respHeader.setId(query.getHeader().getId());
            respHeader.setRd(query.getHeader().isRd());
            for (DnsQuestion q : query.getQuestions()) {
                response.addQuestion(q);
            }
        }
        respHeader.setQr(true); // Is a response
        respHeader.setOpcode(DnsHeader.OPCODE_QUERY);
        respHeader.setRcode(rcode);
        return response;
    }

    public static DnsMessage createSuccessResponse(DnsMessage query) {
        return createResponse(query, DnsHeader.RCODE_NOERROR);
    }

    public static DnsMessage createNxDomainResponse(DnsMessage query) {
        return createResponse(query, DnsHeader.RCODE_NXDOMAIN);
    }

    public static DnsMessage createServFailResponse(DnsMessage query) {
        return createResponse(query, DnsHeader.RCODE_SERVFAIL);
    }

    public static DnsMessage createRefusedResponse(DnsMessage query) {
        return createResponse(query, DnsHeader.RCODE_REFUSED);
    }

    public static DnsMessage createFormErrResponse(DnsMessage query) {
        return createResponse(query, DnsHeader.RCODE_FORMERR);
    }

    /**
     * Formats the DNS message in the style of the BIND 'dig' command.
     */
    public String toDigOutput(long queryTimeMs, String server, int messageSize) {
        StringBuilder sb = new StringBuilder();
        sb.append("\n; <<>> DiG-Java 1.0.0 <<>> ");
        if (!questions.isEmpty()) {
            sb.append(questions.get(0).getName()).append(" ").append(questions.get(0).getType());
        }
        sb.append("\n;; Got answer:\n");
        sb.append(";; ->>HEADER<<- opcode: QUERY, status: ")
          .append(DnsHeader.rcodeToString(header.getRcode()))
          .append(", id: ").append(header.getId()).append("\n");

        sb.append(";; flags: ");
        if (header.isQr()) sb.append("qr ");
        if (header.isAa()) sb.append("aa ");
        if (header.isTc()) sb.append("tc ");
        if (header.isRd()) sb.append("rd ");
        if (header.isRa()) sb.append("ra ");
        sb.append("; QUERY: ").append(questions.size())
          .append(", ANSWER: ").append(answers.size())
          .append(", AUTHORITY: ").append(authorities.size())
          .append(", ADDITIONAL: ").append(additionals.size())
          .append("\n\n");

        if (!questions.isEmpty()) {
            sb.append(";; QUESTION SECTION:\n");
            for (DnsQuestion q : questions) {
                sb.append(";").append(q.toString()).append("\n");
            }
            sb.append("\n");
        }

        if (!answers.isEmpty()) {
            sb.append(";; ANSWER SECTION:\n");
            for (DnsRecord a : answers) {
                sb.append(a.toString()).append("\n");
            }
            sb.append("\n");
        }

        if (!authorities.isEmpty()) {
            sb.append(";; AUTHORITY SECTION:\n");
            for (DnsRecord auth : authorities) {
                sb.append(auth.toString()).append("\n");
            }
            sb.append("\n");
        }

        if (!additionals.isEmpty()) {
            sb.append(";; ADDITIONAL SECTION:\n");
            for (DnsRecord add : additionals) {
                sb.append(add.toString()).append("\n");
            }
            sb.append("\n");
        }

        sb.append(";; Query time: ").append(queryTimeMs).append(" msec\n");
        if (server != null && !server.isEmpty()) {
            sb.append(";; SERVER: ").append(server).append("\n");
        }
        sb.append(";; WHEN: ").append(ZonedDateTime.now().format(DateTimeFormatter.RFC_1123_DATE_TIME)).append("\n");
        sb.append(";; MSG SIZE  rcvd: ").append(messageSize).append("\n");

        return sb.toString();
    }

    @Override
    public String toString() {
        return String.format("DnsMessage[header=%s, questions=%d, answers=%d, authorities=%d, additionals=%d]",
                header, questions.size(), answers.size(), authorities.size(), additionals.size());
    }
}
