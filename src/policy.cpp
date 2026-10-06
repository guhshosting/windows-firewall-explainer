#include "core.h"
#include <algorithm>
#include <iomanip>
#include <netfw.h>
#include <sstream>
#include <stdexcept>
#include <type_traits>
#include <windows.h>
#include <wrl/client.h>
namespace wfe {
using Microsoft::WRL::ComPtr;
static std::string hr_text(HRESULT hr) {
    std::ostringstream s;
    s << "HRESULT 0x" << std::hex << std::setw(8) << std::setfill('0')
      << static_cast<unsigned long>(hr);
    return s.str();
}
struct Com {
    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    Com() {
        if (FAILED(hr))
            throw std::runtime_error("COM initialization: " + hr_text(hr));
    }
    ~Com() { CoUninitialize(); }
    Com(const Com &) = delete;
    Com &operator=(const Com &) = delete;
};
struct String {
    BSTR value = nullptr;
    ~String() { SysFreeString(value); }
    String() = default;
    String(const String &) = delete;
    String &operator=(const String &) = delete;
};
struct Variant {
    VARIANT value;
    Variant() { VariantInit(&value); }
    ~Variant() { VariantClear(&value); }
    Variant(const Variant &) = delete;
    Variant &operator=(const Variant &) = delete;
};
static Field unavailable(HRESULT hr) { return {std::nullopt, "unavailable", hr_text(hr)}; }
template <class F> static Field str(F getter, bool emptyAny = false) {
    String s;
    const HRESULT hr = getter(&s.value);
    if (FAILED(hr))
        return unavailable(hr);
    const auto v = s.value ? utf8(std::wstring(s.value, SysStringLen(s.value))) : std::string{};
    return known(v, v.empty() ? (emptyAny ? "unrestricted" : "empty")
                              : (v == "*" ? "unrestricted" : "value"));
}
template <class T, class F> static Field scalar(F getter) {
    T v = static_cast<T>(1);
    const HRESULT hr = getter(&v);
    return FAILED(hr) ? unavailable(hr) : known(std::to_string(static_cast<long>(v)));
}
template <class F> static Field boolean(F getter) {
    VARIANT_BOOL v{};
    const HRESULT hr = getter(&v);
    return FAILED(hr) ? unavailable(hr) : known(v == VARIANT_FALSE ? "false" : "true");
}
static Field action(Field f) {
    if (f.value) {
        if (*f.value == "0")
            f.value = "block";
        else if (*f.value == "1")
            f.value = "allow";
        else
            f.status = "unknown_value";
    }
    return f;
}
static Record read_rule(INetFwRule *rule) {
    Record r;
#define WFE_STRING(key, method, any) r[key] = str([&](BSTR *v) { return rule->method(v); }, any)
    WFE_STRING("name", get_Name, false);
    WFE_STRING("description", get_Description, false);
    WFE_STRING("local_ports", get_LocalPorts, false);
    WFE_STRING("remote_ports", get_RemotePorts, false);
    WFE_STRING("local_addresses", get_LocalAddresses, false);
    WFE_STRING("remote_addresses", get_RemoteAddresses, false);
    WFE_STRING("application", get_ApplicationName, true);
    WFE_STRING("service", get_ServiceName, true);
    WFE_STRING("interface_types", get_InterfaceTypes, false);
    WFE_STRING("grouping", get_Grouping, false);
    WFE_STRING("icmp_types_codes", get_IcmpTypesAndCodes, false);
#undef WFE_STRING
    r["enabled"] = boolean([&](VARIANT_BOOL *v) { return rule->get_Enabled(v); });
    r["edge_traversal"] = boolean([&](VARIANT_BOOL *v) { return rule->get_EdgeTraversal(v); });
    r["profiles"] = scalar<long>([&](long *v) { return rule->get_Profiles(v); });
    r["protocol"] = scalar<long>([&](long *v) { return rule->get_Protocol(v); });
    const auto &protocolValue = r["protocol"].value;
    if (protocolValue) {
        if (*protocolValue != "6" && *protocolValue != "17" && *protocolValue != "256") {
            for (const auto key : {"local_ports", "remote_ports"}) {
                auto &port = r[key];
                if (port.value)
                    port = {std::nullopt, "not_applicable", {}};
            }
        }
        auto &icmp = r["icmp_types_codes"];
        if (*protocolValue != "1" && *protocolValue != "58" && *protocolValue != "256" &&
            icmp.value)
            icmp = {std::nullopt, "not_applicable", {}};
    }
    r["direction"] = scalar<NET_FW_RULE_DIRECTION>(
        [&](NET_FW_RULE_DIRECTION *v) { return rule->get_Direction(v); });
    auto &direction = r["direction"];
    if (direction.value) {
        if (*direction.value == "1")
            direction.value = "inbound";
        else if (*direction.value == "2")
            direction.value = "outbound";
        else
            direction.status = "unknown_value";
    }
    r["action"] =
        action(scalar<NET_FW_ACTION>([&](NET_FW_ACTION *v) { return rule->get_Action(v); }));
    r["policy_source"] = {};
    r["editable"] = {};
    ComPtr<INetFwRule2> two;
    if (SUCCEEDED(rule->QueryInterface(IID_PPV_ARGS(&two))))
        r["edge_traversal_options"] =
            scalar<long>([&](long *v) { return two->get_EdgeTraversalOptions(v); });
    else
        r["edge_traversal_options"] = {};
    ComPtr<INetFwRule3> three;
    if (SUCCEEDED(rule->QueryInterface(IID_PPV_ARGS(&three)))) {
        r["package_id"] = str([&](BSTR *v) { return three->get_LocalAppPackageId(v); });
        r["local_user_owner"] = str([&](BSTR *v) { return three->get_LocalUserOwner(v); });
        r["local_user_authorized_list"] =
            str([&](BSTR *v) { return three->get_LocalUserAuthorizedList(v); });
        r["remote_user_authorized_list"] =
            str([&](BSTR *v) { return three->get_RemoteUserAuthorizedList(v); });
        r["remote_machine_authorized_list"] =
            str([&](BSTR *v) { return three->get_RemoteMachineAuthorizedList(v); });
        r["secure_flags"] = scalar<long>([&](long *v) { return three->get_SecureFlags(v); });
    } else
        for (const auto key :
             {"package_id", "local_user_owner", "local_user_authorized_list",
              "remote_user_authorized_list", "remote_machine_authorized_list", "secure_flags"})
            r[key] = {};
    // Interfaces is a VARIANT containing interface bindings; do not imply unrestricted when not
    // decoded.
    r["interface_bindings"] = {std::nullopt, "unavailable",
                               "Interface binding SAFEARRAY is not decoded"};
    return r;
}
Snapshot inspect(bool enumerate) {
    Com apartment;
    ComPtr<INetFwPolicy2> policy;
    HRESULT hr = CoCreateInstance(__uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER,
                                  IID_PPV_ARGS(&policy));
    if (FAILED(hr))
        throw std::runtime_error("Firewall policy unavailable: " + hr_text(hr));
    Snapshot s;
    s.policy["current_profile_mask"] =
        scalar<long>([&](long *v) { return policy->get_CurrentProfileTypes(v); });
    NET_FW_MODIFY_STATE modify{};
    const HRESULT modifyHr = policy->get_LocalPolicyModifyState(&modify);
    s.policy["local_policy_modify_state"] =
        FAILED(modifyHr) ? unavailable(modifyHr) : known(std::to_string(modify));
    s.policy["local_policy_modify_state_coverage"] =
        FAILED(modifyHr)
            ? unavailable(modifyHr)
            : known(modifyHr == S_FALSE ? "some active profiles" : "all active profiles");
    s.policy["local_policy_modify_state_scope"] =
        known("Active profiles only; 0=OK, 1=Group Policy override, 2=inbound blocked. Not rule "
              "provenance or proof of editability.");
    s.policy["local_rule_merge"] = {};
    for (const auto &p : std::vector<std::pair<NET_FW_PROFILE_TYPE2, std::string>>{
             {NET_FW_PROFILE2_DOMAIN, "Domain"},
             {NET_FW_PROFILE2_PRIVATE, "Private"},
             {NET_FW_PROFILE2_PUBLIC, "Public"}}) {
        Record r;
        r["name"] = known(p.second);
        r["mask"] = known(std::to_string(p.first));
        r["enabled"] =
            boolean([&](VARIANT_BOOL *v) { return policy->get_FirewallEnabled(p.first, v); });
        r["block_all_inbound"] = boolean(
            [&](VARIANT_BOOL *v) { return policy->get_BlockAllInboundTraffic(p.first, v); });
        r["default_inbound"] = action(scalar<NET_FW_ACTION>(
            [&](NET_FW_ACTION *v) { return policy->get_DefaultInboundAction(p.first, v); }));
        r["default_outbound"] = action(scalar<NET_FW_ACTION>(
            [&](NET_FW_ACTION *v) { return policy->get_DefaultOutboundAction(p.first, v); }));
        r["excluded_interfaces"] = {};
        r["policy_source"] = {};
        r["local_rule_merge"] = {};
        s.profiles.push_back(std::move(r));
    }
    if (!enumerate)
        return s;
    ComPtr<INetFwRules> rules;
    hr = policy->get_Rules(&rules);
    if (FAILED(hr))
        throw std::runtime_error("Rules unavailable: " + hr_text(hr));
    ComPtr<IUnknown> enumerator;
    hr = rules->get__NewEnum(&enumerator);
    if (FAILED(hr))
        throw std::runtime_error("Rule enumerator unavailable: " + hr_text(hr));
    ComPtr<IEnumVARIANT> items;
    hr = enumerator.As(&items);
    if (FAILED(hr))
        throw std::runtime_error("Rule enumeration unavailable: " + hr_text(hr));
    for (;;) {
        Variant v;
        ULONG fetched = 0;
        hr = items->Next(1, &v.value, &fetched);
        if (FAILED(hr))
            throw std::runtime_error("Incomplete rule enumeration: " + hr_text(hr));
        if (!fetched)
            break;
        ComPtr<INetFwRule> rule;
        IUnknown *item = v.value.vt == VT_DISPATCH
                             ? static_cast<IUnknown *>(v.value.pdispVal)
                             : (v.value.vt == VT_UNKNOWN ? v.value.punkVal : nullptr);
        if (!item || FAILED(item->QueryInterface(IID_PPV_ARGS(&rule))))
            throw std::runtime_error("Unexpected rule enumeration value");
        s.rules.push_back(read_rule(rule.Get()));
    }
    std::sort(s.rules.begin(), s.rules.end(),
              [](const Record &a, const Record &b) { return json(a) < json(b); });
    return s;
}
} // namespace wfe
