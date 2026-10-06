#include "core.h"
#include <algorithm>
#include <iostream>
#include <set>
#include <sstream>
#include <stdexcept>
#include <windows.h>
using namespace wfe;
// Use UTF-16 for the console without changing its code page; UTF-8 bytes for redirection.
static bool emit(const std::string &text, bool error = false) {
    const HANDLE handle = GetStdHandle(error ? STD_ERROR_HANDLE : STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (GetConsoleMode(handle, &mode)) {
        const auto value = wide(text);
        size_t offset = 0;
        while (offset < value.size()) {
            DWORD count = static_cast<DWORD>((std::min)(value.size() - offset, size_t{16000}));
            if (offset + count < value.size() && value[offset + count - 1] >= 0xD800 &&
                value[offset + count - 1] <= 0xDBFF)
                --count;
            DWORD written = 0;
            if (!WriteConsoleW(handle, value.data() + offset, count, &written, nullptr) || !written)
                return false;
            offset += written;
        }
    } else {
        size_t offset = 0;
        while (offset < text.size()) {
            const DWORD count = static_cast<DWORD>((std::min)(text.size() - offset, size_t{65536}));
            DWORD written = 0;
            if (!WriteFile(handle, text.data() + offset, count, &written, nullptr) || !written)
                return false;
            offset += written;
        }
    }
    return true;
}
static constexpr const char *help =
    "windows-firewall-explainer 1.0.0\nUsage:\n  windows-firewall-explainer status [--json]\n  "
    "windows-firewall-explainer rules [--json]\n  windows-firewall-explainer explain --direction "
    "inbound|outbound --protocol tcp|udp\n    --profile domain|private|public [--local-port "
    "0..65535] [--remote-port 0..65535]\n    [--local-ip numeric-IP] [--remote-ip numeric-IP]\n    "
    "[--application absolute-path] [--service name] [--json]\n  windows-firewall-explainer --help "
    "| --version\nRead-only configuration inspection. No traffic, DNS, or runtime packet "
    "verdict.\nExit codes: 0 success, 2 invalid arguments, 3 inspection/internal failure.\n";
static void print_record(std::ostream &out, const Record &r) {
    for (const auto &p : r)
        out << "  " << p.first << ": " << (p.second.value ? *p.second.value : "unavailable") << " ["
            << p.second.status << "]" << (p.second.error.empty() ? "" : " " + p.second.error)
            << '\n';
}
int wmain(int argc, wchar_t **argv) {
    bool asJson = false;
    std::ostringstream out;
    try {
        std::vector<std::string> args;
        for (int i = 1; i < argc; ++i)
            args.push_back(utf8(argv[i]));
        if (args.empty()) {
            out << help;
            return emit(out.str()) ? 2 : 3;
        }
        if (args.size() == 1 && args[0] == "--help") {
            out << help;
            return emit(out.str()) ? 0 : 3;
        }
        if (args.size() == 1 && args[0] == "--version") {
            out << "windows-firewall-explainer 1.0.0\n";
            return emit(out.str()) ? 0 : 3;
        }
        for (const auto &a : args)
            if (a == "--json")
                asJson = true;
        const auto mode = args[0];
        if (mode != "status" && mode != "rules" && mode != "explain")
            throw std::invalid_argument("Unknown command: " + mode);
        Tuple t;
        std::set<std::string> seen;
        for (size_t i = 1; i < args.size(); ++i) {
            const auto &key = args[i];
            if (!seen.insert(key).second)
                throw std::invalid_argument("Duplicate option: " + key);
            if (key == "--json")
                continue;
            if (mode != "explain")
                throw std::invalid_argument("Unexpected option: " + key);
            if (i + 1 == args.size())
                throw std::invalid_argument("Missing value: " + key);
            const auto &v = args[++i];
            if (key == "--direction") {
                if (v != "inbound" && v != "outbound")
                    throw std::invalid_argument("Direction must be inbound or outbound");
                t.direction = v;
            } else if (key == "--protocol")
                t.protocol = protocol(v);
            else if (key == "--profile") {
                if (v == "domain")
                    t.profile = 1;
                else if (v == "private")
                    t.profile = 2;
                else if (v == "public")
                    t.profile = 4;
                else
                    throw std::invalid_argument("Profile must be domain, private or public");
            } else if (key == "--local-port")
                t.local_port = number(v, 65535);
            else if (key == "--remote-port")
                t.remote_port = number(v, 65535);
            else if (key == "--local-ip" || key == "--remote-ip") {
                if (!valid_ip(v))
                    throw std::invalid_argument("Numeric IP required: " + v);
                (key == "--local-ip" ? t.local_ip : t.remote_ip) = v;
            } else if (key == "--application") {
                if (v.size() < 3 ||
                    !((v[0] >= 'A' && v[0] <= 'Z') || (v[0] >= 'a' && v[0] <= 'z')) ||
                    v[1] != ':' || (v[2] != '\\' && v[2] != '/'))
                    throw std::invalid_argument("Application requires an absolute drive path");
                t.application = v;
            } else if (key == "--service") {
                if (v.empty())
                    throw std::invalid_argument("Service cannot be empty");
                t.service = v;
            } else
                throw std::invalid_argument("Unknown option: " + key);
        }
        if (mode == "explain" && (t.direction.empty() || !t.protocol || !t.profile))
            throw std::invalid_argument("Explain requires direction, protocol and profile");
        auto s = inspect(mode != "status");
        std::vector<Record> analysis;
        if (mode == "explain")
            for (size_t i = 0; i < s.rules.size(); ++i) {
                const auto rel = relevance(s.rules[i], t);
                Record r;
                r["rule_index"] = known(std::to_string(i));
                r["name"] = s.rules[i].at("name");
                r["action"] = s.rules[i].at("action");
                r["category"] = known(rel.category);
                std::string reasons;
                for (const auto &reason : rel.reasons) {
                    if (!reasons.empty())
                        reasons += "; ";
                    reasons += reason;
                }
                r["reasons"] = known(reasons);
                analysis.push_back(std::move(r));
            }
        if (asJson) {
            out << "{\"schema_version\":1,\"version\":\"1.0.0\",\"mode\":" << quote(mode)
                << ",\"limitations\":" << quote(limitation) << ",\"policy\":" << json(s.policy)
                << ",\"profiles\":" << json(s.profiles);
            if (mode != "status")
                out << ",\"rules\":" << json(s.rules);
            if (mode == "explain") {
                Record tuple;
                tuple["direction"] = known(t.direction);
                tuple["protocol"] = known(std::to_string(t.protocol));
                tuple["profile"] = known(std::to_string(t.profile));
                tuple["local_port"] = t.local_port ? known(std::to_string(*t.local_port))
                                                   : Field{std::nullopt, "not_supplied", {}};
                tuple["remote_port"] = t.remote_port ? known(std::to_string(*t.remote_port))
                                                     : Field{std::nullopt, "not_supplied", {}};
                for (const auto &p :
                     std::vector<std::pair<std::string, std::optional<std::string>>>{
                         {"local_ip", t.local_ip},
                         {"remote_ip", t.remote_ip},
                         {"application", t.application},
                         {"service", t.service}})
                    tuple[p.first] =
                        p.second ? known(*p.second) : Field{std::nullopt, "not_supplied", {}};
                out << ",\"tuple\":" << json(tuple) << ",\"analysis\":" << json(analysis);
            }
            out << "}\n";
        } else {
            out << limitation << "\nPolicy:\n";
            print_record(out, s.policy);
            for (const auto &p : s.profiles) {
                out << "Profile:\n";
                print_record(out, p);
            }
            if (mode == "rules")
                for (const auto &r : s.rules) {
                    out << "Rule:\n";
                    print_record(out, r);
                }
            if (mode == "explain")
                for (const auto &r : analysis) {
                    out << "Relevance:\n";
                    print_record(out, r);
                }
            if (mode != "status" && s.rules.empty())
                out << "No locally visible rules. Defaults remain configuration only.\n";
        }
        return emit(out.str()) ? 0 : 3;
    } catch (const std::exception &e) {
        const int code = dynamic_cast<const std::invalid_argument *>(&e) ? 2 : 3;
        if (asJson)
            out << "{\"schema_version\":1,\"error\":" << quote(e.what())
                << ",\"exit_code\":" << code << "}\n";
        else
            out << "Error: " << e.what() << '\n';
        return emit(out.str(), !asJson) ? code : 3;
    }
}
