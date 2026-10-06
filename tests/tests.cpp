#include "core.h"
#include <cstdio>
#include <iostream>
#include <stdexcept>
using namespace wfe;
static int checks = 0;
static void check(bool value) {
    ++checks;
    if (!value)
        throw std::runtime_error("Check failed: " + std::to_string(checks));
}
int main() {
    try {
        check(protocol("TCP") == 6);
        check(protocol("udp") == 17);
        check(profile_matches(7, 4));
        check(!profile_matches(1, 4));
        check(profile_matches(0x7fffffff, 2));
        check(ports(known("80,443,1000-2000"), 1500) == Match::yes);
        check(ports(known("80,443"), 81) == Match::no);
        check(ports(known("RPC"), 80) == Match::unknown);
        check(ports({}, 80) == Match::unknown);
        check(ports(known("*"), {}) == Match::yes);
        check(ports(known(""), 80) == Match::unknown);
        check(ports(known("90-80"), 85) == Match::unknown);
        check(valid_ip("192.0.2.1"));
        check(valid_ip("2001:db8::1"));
        check(!valid_ip("example.com"));
        check(!valid_ip("999.1.1.1"));
        check(addresses(known("192.0.2.0/24"), "192.0.2.7") == Match::yes);
        check(addresses(known("192.0.2.0/255.255.255.0"), "192.0.2.7") == Match::yes);
        check(addresses(known("192.0.2.1-192.0.2.10"), "192.0.2.11") == Match::no);
        check(addresses(known("2001:db8::/32"), "2001:db8::1") == Match::yes);
        check(addresses(known("2001:db8::1-2001:db8::f"), "2001:db8::8") == Match::yes);
        check(addresses(known("LocalSubnet"), "192.0.2.1") == Match::unknown);
        check(addresses({}, "192.0.2.1") == Match::unknown);
        check(addresses(known("::/0"), "2001:db8::1") == Match::yes);
        check(addresses(known("2001:db8::1/128"), "2001:db8::2") == Match::no);
        check(addresses(known("192.0.2.0/33"), "192.0.2.1") == Match::unknown);
        check(addresses(known("192.0.2.0/255.0.255.0"), "192.0.2.1") == Match::unknown);
        check(addresses(known("192.0.2.10-192.0.2.1"), "192.0.2.5") == Match::unknown);
        check(addresses(known("192.0.2.1"), "::1") == Match::no);
        check(addresses(known("LocalSubnet,192.0.2.1"), "192.0.2.1") == Match::yes);
        check(ports(known("0,65535"), 65535) == Match::yes);
        check(ports(known("RPC,443"), 443) == Match::yes);
        check(ports(known("65536"), 443) == Match::unknown);
        Record r;
        for (const auto key : {"local_ports", "remote_ports", "local_addresses", "remote_addresses",
                               "application", "service"})
            r[key] = known("*");
        r["enabled"] = known("true");
        r["direction"] = known("inbound");
        r["profiles"] = known("7");
        r["protocol"] = known("6");
        r["interface_types"] = known("All");
        Tuple t;
        t.direction = "inbound";
        t.protocol = 6;
        t.profile = 4;
        check(relevance(r, t).category == "match");
        r["profiles"] = known("1");
        check(relevance(r, t).category == "excluded");
        r["profiles"] = known("7");
        r["protocol"] = known("17");
        check(relevance(r, t).category == "excluded");
        r["protocol"] = known("256");
        check(relevance(r, t).category == "match");
        r["protocol"] = known("6");
        r["package_id"] = known("S-1-15-example");
        check(relevance(r, t).category == "ambiguous");
        r["package_id"] = known("");
        r["secure_flags"] = known("1");
        check(relevance(r, t).category == "ambiguous");
        r["secure_flags"] = known("0");
        r["enabled"] = known("false");
        check(relevance(r, t).category == "excluded");
        r["enabled"] = known("true");
        t.direction = "outbound";
        check(relevance(r, t).category == "excluded");
        t.direction = "inbound";
        r["application"] = known("C:\\a.exe");
        check(relevance(r, t).category == "ambiguous");
        t.application = "c:\\A.exe";
        check(relevance(r, t).category == "match");
        t.application = "C:\\b.exe";
        check(relevance(r, t).category == "excluded");
        t.application = "C:\\a.exe";
        r["service"] = known("service");
        check(relevance(r, t).category == "ambiguous");
        t.service = "other";
        check(relevance(r, t).category == "excluded");
        t.service = "SERVICE";
        check(relevance(r, t).category == "match");
        r["local_ports"] = {};
        check(relevance(r, t).category == "ambiguous");
        check(relevance({}, t).category == "ambiguous");
        check(json(std::vector<Record>{}) == "[]");
        check(json(Record{{"missing", {}}}).find("\"value\":null") != std::string::npos);
        check(quote("a\n\"\\") == "\"a\\u000a\\\"\\\\\"");
        check(utf8(wide("hello \xE2\x98\x83")) == "hello \xE2\x98\x83");
        bool rejected = false;
        try {
            number("65536", 65535);
        } catch (const std::invalid_argument &) {
            rejected = true;
        }
        check(rejected);
        rejected = false;
        try {
            protocol("icmp");
        } catch (const std::invalid_argument &) {
            rejected = true;
        }
        check(rejected);
        std::cout << checks << " checks passed\n";
        return 0;
    } catch (const std::exception &e) {
        std::fprintf(stderr, "%s\n", e.what());
        return 1;
    }
}
