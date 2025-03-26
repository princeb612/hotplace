/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/io/system/socket.hpp>

namespace hotplace {
namespace io {

socket_advisor socket_advisor::_instance;

socket_advisor::socket_advisor() {}

socket_advisor* socket_advisor::get_instance() {
    _instance.build();
    return &_instance;
}

struct socket_resource {
    int code;
    const char* desc;
};
#define DEFINE_ENTRY(x) \
    { x, #x }

const socket_resource socket_resource_family[] = {
    DEFINE_ENTRY(AF_UNSPEC),     // 0
    DEFINE_ENTRY(AF_INET),       // 2
    DEFINE_ENTRY(AF_IPX),        // 6
    DEFINE_ENTRY(AF_APPLETALK),  // 16
    {17, "AF_NETBIOS"},          // 17
    DEFINE_ENTRY(AF_INET6),      // 23
    DEFINE_ENTRY(AF_IRDA),       // 26
    {32, "AF_BTH"},              // 32
};
const socket_resource socket_resource_type[] = {
    DEFINE_ENTRY(SOCK_STREAM),     // 1
    DEFINE_ENTRY(SOCK_DGRAM),      // 2
    DEFINE_ENTRY(SOCK_RAW),        // 3
    DEFINE_ENTRY(SOCK_RDM),        // 4
    DEFINE_ENTRY(SOCK_SEQPACKET),  // 5
};
const socket_resource socket_resource_protocol[] = {
    DEFINE_ENTRY(IPPROTO_ICMP),    // 1
    DEFINE_ENTRY(IPPROTO_IGMP),    // 2
    {3, "BTHPROTO_RFCOMM"},        // 3
    DEFINE_ENTRY(IPPROTO_TCP),     // 6
    DEFINE_ENTRY(IPPROTO_UDP),     // 17
    DEFINE_ENTRY(IPPROTO_ICMPV6),  // 58
    {113, "IPPROTO_RM"},           // 113
};

void socket_advisor::build() {
    if (_family.empty()) {
        critical_section_guard guard(_lock);
        if (_family.empty()) {
            for (auto i = 0; i < RTL_NUMBER_OF(socket_resource_family); i++) {
                const socket_resource& item = socket_resource_family[i];
                _family.insert({item.code, item.desc});
            }
            for (auto i = 0; i < RTL_NUMBER_OF(socket_resource_type); i++) {
                const socket_resource& item = socket_resource_type[i];
                _type.insert({item.code, item.desc});
            }
            for (auto i = 0; i < RTL_NUMBER_OF(socket_resource_protocol); i++) {
                const socket_resource& item = socket_resource_protocol[i];
                _protocol.insert({item.code, item.desc});
            }
        }
    }
}

std::string socket_advisor::nameof_family(int code) {
    std::string value;
    auto iter = _family.find(code);
    if (_family.end() != iter) {
        value = iter->second;
    }
    return value;
}

std::string socket_advisor::nameof_type(int code) {
    std::string value;
    auto iter = _type.find(code);
    if (_type.end() != iter) {
        value = iter->second;
    }
    return value;
}

std::string socket_advisor::nameof_protocol(int code) {
    std::string value;
    auto iter = _protocol.find(code);
    if (_protocol.end() != iter) {
        value = iter->second;
    }
    return value;
}

}  // namespace io
}  // namespace hotplace
