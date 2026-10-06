#include "core.h"
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 6101)
#endif
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#ifdef _MSC_VER
#pragma warning(pop)
#endif
#include <algorithm>
#include <array>
#include <charconv>
#include <sstream>
#include <stdexcept>
namespace wfe {
Field known(std::string v, std::string s) { return {std::move(v), std::move(s), {}}; }
std::string utf8(const std::wstring &s) {
    if (s.empty())
        return {};
    if (s.size() > INT_MAX)
        throw std::runtime_error("Text too large");
    const int n = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, s.data(),
                                      static_cast<int>(s.size()), nullptr, 0, nullptr, nullptr);
    if (!n)
        throw std::runtime_error("Invalid UTF-16");
    std::string r(static_cast<size_t>(n), '\0');
    if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()),
                             r.data(), n, nullptr, nullptr))
        throw std::runtime_error("UTF conversion failed");
    return r;
}
std::wstring wide(const std::string &s) {
    if (s.empty())
        return {};
    if (s.size() > INT_MAX)
        throw std::runtime_error("Text too large");
    const int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(),
                                      static_cast<int>(s.size()), nullptr, 0);
    if (!n)
        throw std::runtime_error("Invalid UTF-8");
    std::wstring r(static_cast<size_t>(n), L'\0');
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()),
                             r.data(), n))
        throw std::runtime_error("UTF conversion failed");
    return r;
}
std::string quote(const std::string &s) {
    std::string r = "\"";
    constexpr char hex[] = "0123456789abcdef";
    for (unsigned char c : s) {
        if (c == '"' || c == '\\') {
            r += '\\';
            r += static_cast<char>(c);
        } else if (c < 32) {
            r += "\\u00";
            r += hex[c / 16];
            r += hex[c % 16];
        } else
            r += static_cast<char>(c);
    }
    return r + '"';
}
std::string json(const Record &r) {
    std::string out = "{";
    bool first = true;
    for (const auto &p : r) {
        if (!first)
            out += ',';
        first = false;
        out += quote(p.first) +
               ":{\"value\":" + (p.second.value ? quote(*p.second.value) : "null") +
               ",\"status\":" + quote(p.second.status);
        if (!p.second.error.empty())
            out += ",\"error\":" + quote(p.second.error);
        out += '}';
    }
    return out + '}';
}
std::string json(const std::vector<Record> &r) {
    std::string out = "[";
    for (size_t i = 0; i < r.size(); ++i) {
        if (i)
            out += ',';
        out += json(r[i]);
    }
    return out + ']';
}
int number(const std::string &s, int maximum) {
    int n = 0;
    const auto result = std::from_chars(s.data(), s.data() + s.size(), n);
    if (s.empty() || result.ec != std::errc{} || result.ptr != s.data() + s.size() || n < 0 ||
        n > maximum)
        throw std::invalid_argument("Invalid numeric value: " + s);
    return n;
}
int protocol(const std::string &s) {
    if (s == "tcp" || s == "TCP")
        return 6;
    if (s == "udp" || s == "UDP")
        return 17;
    throw std::invalid_argument("Protocol must be TCP or UDP");
}
struct IP {
    std::array<unsigned char, 16> bytes{};
    int size = 0;
};
static std::optional<IP> parse_ip(const std::string &s) {
    IP ip;
    const auto w = wide(s);
    if (InetPtonW(AF_INET, w.c_str(), ip.bytes.data()) == 1) {
        ip.size = 4;
        return ip;
    }
    if (InetPtonW(AF_INET6, w.c_str(), ip.bytes.data()) == 1) {
        ip.size = 16;
        return ip;
    }
    return {};
}
bool valid_ip(const std::string &s) { return parse_ip(s).has_value(); }
bool profile_matches(int mask, int profile) {
    return mask == 0x7fffffff ||
           (static_cast<unsigned>(mask) & static_cast<unsigned>(profile)) != 0;
}
static std::vector<std::string> split(const std::string &s) {
    std::vector<std::string> out;
    std::istringstream in(s);
    std::string part;
    while (std::getline(in, part, ',')) {
        const auto b = part.find_first_not_of(" \t");
        const auto e = part.find_last_not_of(" \t");
        out.push_back(b == std::string::npos ? "" : part.substr(b, e - b + 1));
    }
    return out;
}
Match ports(const Field &f, const std::optional<int> &port) {
    if (!f.value)
        return Match::unknown;
    if (*f.value == "*")
        return Match::yes;
    if (f.value->empty())
        return Match::unknown;
    if (!port)
        return Match::unknown;
    bool unknown = false;
    for (const auto &s : split(*f.value)) {
        try {
            const auto dash = s.find('-');
            const int lo = number(s.substr(0, dash), 65535);
            const int hi = dash == std::string::npos ? lo : number(s.substr(dash + 1), 65535);
            if (lo > hi) {
                unknown = true;
                continue;
            }
            if (*port >= lo && *port <= hi)
                return Match::yes;
        } catch (const std::invalid_argument &) {
            unknown = true;
        }
    }
    return unknown ? Match::unknown : Match::no;
}
static bool less_equal(const IP &a, const IP &b) {
    return !std::lexicographical_compare(b.bytes.begin(), b.bytes.begin() + b.size, a.bytes.begin(),
                                         a.bytes.begin() + a.size);
}
Match addresses(const Field &f, const std::optional<std::string> &address) {
    if (!f.value)
        return Match::unknown;
    if (*f.value == "*")
        return Match::yes;
    if (!address || f.value->empty())
        return Match::unknown;
    const auto ip = parse_ip(*address);
    if (!ip)
        return Match::unknown;
    bool unknown = false;
    for (const auto &s : split(*f.value)) {
        const auto slash = s.find('/');
        const auto dash = s.find('-');
        const auto base = parse_ip(s.substr(0, std::min(slash, dash)));
        if (!base) {
            unknown = true;
            continue;
        }
        if (base->size != ip->size)
            continue;
        if (slash != std::string::npos) {
            try {
                const auto suffix = s.substr(slash + 1);
                const auto mask = parse_ip(suffix);
                int bits = 0;
                if (mask) {
                    if (mask->size != base->size) {
                        unknown = true;
                        continue;
                    }
                    bool zero = false;
                    for (int i = 0; i < mask->size; ++i)
                        for (int bit = 7; bit >= 0; --bit) {
                            const bool one = (mask->bytes[static_cast<size_t>(i)] &
                                              (1U << static_cast<unsigned>(bit))) != 0;
                            if (one && zero)
                                throw std::invalid_argument("Noncontiguous mask");
                            if (one)
                                ++bits;
                            else
                                zero = true;
                        }
                } else
                    bits = number(suffix, base->size * 8);
                bool equal = true;
                for (int bit = 0; bit < bits; ++bit)
                    if ((base->bytes[static_cast<size_t>(bit / 8)] &
                         (1U << static_cast<unsigned>(7 - bit % 8))) !=
                        (ip->bytes[static_cast<size_t>(bit / 8)] &
                         (1U << static_cast<unsigned>(7 - bit % 8))))
                        equal = false;
                if (equal)
                    return Match::yes;
            } catch (const std::invalid_argument &) {
                unknown = true;
            }
        } else if (dash != std::string::npos) {
            const auto end = parse_ip(s.substr(dash + 1));
            if (!end || end->size != base->size || !less_equal(*base, *end)) {
                unknown = true;
                continue;
            }
            if (less_equal(*base, *ip) && less_equal(*ip, *end))
                return Match::yes;
        } else if (base->bytes == ip->bytes)
            return Match::yes;
    }
    return unknown ? Match::unknown : Match::no;
}
static Field field(const Record &r, const std::string &key) {
    const auto it = r.find(key);
    return it == r.end() ? Field{} : it->second;
}
static bool equal_text(const std::string &a, const std::string &b) {
    const auto aw = wide(a), bw = wide(b);
    return CompareStringOrdinal(aw.c_str(), static_cast<int>(aw.size()), bw.c_str(),
                                static_cast<int>(bw.size()), TRUE) == CSTR_EQUAL;
}
Relevance relevance(const Record &r, const Tuple &t) {
    Relevance result;
    bool no = false, unknown = false;
    const auto check = [&](Match m, const std::string &name) {
        if (m == Match::no) {
            no = true;
            result.reasons.push_back(name + ": excluded");
        } else if (m == Match::unknown) {
            unknown = true;
            result.reasons.push_back(name + ": unavailable or requires context");
        }
    };
    const auto eq = [&](const std::string &key, const std::string &value) {
        const auto f = field(r, key);
        check(!f.value ? Match::unknown : (*f.value == value ? Match::yes : Match::no), key);
    };
    eq("enabled", "true");
    eq("direction", t.direction);
    for (const auto &key : {"profiles", "protocol"}) {
        const auto f = field(r, key);
        if (!f.value) {
            check(Match::unknown, key);
            continue;
        }
        try {
            const int n = number(*f.value, INT_MAX);
            check(std::string(key) == "profiles"
                      ? (profile_matches(n, t.profile) ? Match::yes : Match::no)
                      : ((n == 256 || n == t.protocol) ? Match::yes : Match::no),
                  key);
        } catch (const std::invalid_argument &) {
            check(Match::unknown, key);
        }
    }
    check(ports(field(r, "local_ports"), t.local_port), "local_ports");
    check(ports(field(r, "remote_ports"), t.remote_port), "remote_ports");
    check(addresses(field(r, "local_addresses"), t.local_ip), "local_addresses");
    check(addresses(field(r, "remote_addresses"), t.remote_ip), "remote_addresses");
    for (const auto &p : std::vector<std::pair<std::string, std::optional<std::string>>>{
             {"application", t.application}, {"service", t.service}}) {
        const auto f = field(r, p.first);
        check(!f.value ? Match::unknown
                       : (f.value->empty() || *f.value == "*"
                              ? Match::yes
                              : (!p.second
                                     ? Match::unknown
                                     : (equal_text(*f.value, *p.second) ? Match::yes : Match::no))),
              p.first);
    }
    const auto interfaces = field(r, "interface_types");
    if (!interfaces.value || *interfaces.value != "All")
        check(Match::unknown, "interface_types");
    for (const auto key : {"package_id", "local_user_owner", "local_user_authorized_list",
                           "remote_user_authorized_list", "remote_machine_authorized_list"}) {
        const auto it = r.find(key);
        if (it != r.end() && (!it->second.value || !it->second.value->empty()))
            check(Match::unknown, key);
    }
    const auto security = r.find("secure_flags");
    if (security != r.end() && (!security->second.value || *security->second.value != "0"))
        check(Match::unknown, "secure_flags");
    result.category = no ? "excluded" : unknown ? "ambiguous" : "match";
    result.reasons.push_back("Interface bindings and runtime policy are not evaluated; "
                             "category describes inspected configuration fields only");
    return result;
}
} // namespace wfe
