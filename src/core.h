#pragma once
#include <map>
#include <optional>
#include <string>
#include <vector>
namespace wfe {
struct Field {
    std::optional<std::string> value;
    std::string status = "unavailable";
    std::string error;
};
using Record = std::map<std::string, Field>;
struct Snapshot {
    std::vector<Record> profiles, rules;
    Record policy;
    Snapshot() = default;
    // MSVC std::map move constructs an allocated sentinel and can throw.
    Snapshot(Snapshot &&) noexcept(false) = default; // NOLINT(bugprone-unsafe-to-allow-exceptions)
    Snapshot &
    operator=(Snapshot &&) noexcept(false) = default; // NOLINT(bugprone-unsafe-to-allow-exceptions)
    Snapshot(const Snapshot &) = default;
    Snapshot &operator=(const Snapshot &) = default;
};
struct Tuple {
    std::string direction;
    int protocol = 0;
    int profile = 0;
    std::optional<int> local_port, remote_port;
    std::optional<std::string> local_ip, remote_ip, application, service;
};
enum class Match : unsigned char { yes, no, unknown };
struct Relevance {
    std::string category;
    std::vector<std::string> reasons;
};
Field known(std::string value, std::string status = "value");
std::string utf8(const std::wstring &s);
std::wstring wide(const std::string &s);
std::string quote(const std::string &s);
std::string json(const Record &r);
std::string json(const std::vector<Record> &r);
int number(const std::string &s, int maximum);
int protocol(const std::string &s);
bool valid_ip(const std::string &s);
bool profile_matches(int mask, int profile);
Match ports(const Field &field, const std::optional<int> &port);
Match addresses(const Field &field, const std::optional<std::string> &ip);
Relevance relevance(const Record &rule, const Tuple &tuple);
Snapshot inspect(bool rules);
inline constexpr const char *limitation =
    "Configuration-level relevance only; no packet verdict. WFP runtime filters, third-party "
    "filters, IPsec, service restrictions, interface selection, policy merging and dynamic state "
    "are not fully represented. Rule source/editability and per-profile local-rule merging are "
    "unavailable through this inspection. Snapshot is not atomic.";
} // namespace wfe
