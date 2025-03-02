/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/basic/util/ipaddr_acl.hpp>

namespace hotplace {
namespace net {

ipaddr_acl::ipaddr_acl() : _mode(ipaddr_acl_t::blacklist) {
    // do nothing
}

ipaddr_acl::ipaddr_acl(ipaddr_acl& obj) {
    critical_section_guard guard(obj._lock);
    _mode = obj._mode;
    _single_type_rule = obj._single_type_rule;
    _range_type_rule = obj._range_type_rule;
}

ipaddr_acl::~ipaddr_acl() {
    // do nothing
}

return_t ipaddr_acl::setmode(int mode) {
    return_t ret = errorcode_t::success;

    _mode = mode;
    return ret;
}

return_t ipaddr_acl::add_rule(const char* addr, bool allow) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == addr) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        const char* is_cidr = strstr(addr, "/");
        if (nullptr != is_cidr) {
            std::string addr_new(addr, is_cidr - addr);
            std::string addr_cidr(is_cidr + 1);
            if (addr_cidr.empty()) { /* 1.2.3.4/ */
                ret = errorcode_t::invalid_parameter;
                __leave2;
            }
            /* add_rule(1.2.3.4/16, allow) calls add_rule(1.2.3.4, 16, allow) */
            ret = add_rule(addr_new.c_str(), atoi(addr_cidr.c_str()), allow);
            if (errorcode_t::success != ret) {
                __leave2;
            }
        } else {
            int family = 0;
            ipaddr_t address = convert_addr(addr, family);
#ifndef SUPPORT_IPV6
            if (AF_INET6 == family) {
                ret = errorcode_t::not_supported;
                __leave2;
            }
#endif
            ipaddress_rule_item_t item;
            item.mode = ipaddr_acl_t::single_addr;
            item.addr = 0;
            item.allow = allow;

            critical_section_guard guard(_lock);
            ipaddress_rule_map_pib_t pib = _single_type_rule.insert(std::make_pair(address, item));
            if (false == pib.second) {
                ret = errorcode_t::already_exist;
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t ipaddr_acl::add_rule(const sockaddr_storage_t* sockaddr, bool allow) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == sockaddr) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        int family = 0;
        ipaddr_t address = convert_sockaddr(sockaddr, family);
#ifndef SUPPORT_IPV6
        if (AF_INET6 == family) {
            ret = errorcode_t::not_supported;
            __leave2;
        }
#endif
        ipaddress_rule_item_t item;
        item.mode = ipaddr_acl_t::single_addr;
        item.addr = 0;
        item.allow = allow;

        critical_section_guard guard(_lock);
        ipaddress_rule_map_pib_t pib = _single_type_rule.insert(std::make_pair(address, item));
        if (false == pib.second) {
            ret = errorcode_t::already_exist;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t ipaddr_acl::add_rule(const char* addr, int mask, bool allow) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == addr) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        int family = 0;
        ipaddr_t address = convert_addr(addr, family);
#ifndef SUPPORT_IPV6
        if (AF_INET6 == family) {
            ret = errorcode_t::not_supported;
            __leave2;
        }
#endif
        ipaddr_t subnet_mask = 0;
        if (AF_INET6 == family) {
            subnet_mask = t_cidr_subnet_mask<ipaddr_t>(mask);
        } else {
            subnet_mask = t_cidr_subnet_mask<uint32>(mask);
        }
        ipaddr_t address_from = (address & subnet_mask);
        ipaddr_t address_to = (address & subnet_mask) | ~subnet_mask;
        if (AF_INET == family) {
            address_from &= 0xffffffff;
            address_to &= 0xffffffff;
        }

        ipaddress_rule_item_t item;
        item.mode = ipaddr_acl_t::cidr_addr;
        item.addr = address_to;
        item.allow = allow;

        critical_section_guard guard(_lock);
        ipaddress_rule_map_pib_t pib = _range_type_rule.insert(std::make_pair(address_from, item));
        if (false == pib.second) {
            ret = errorcode_t::already_exist;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t ipaddr_acl::add_rule(const sockaddr_storage_t* sockaddr, int mask, bool allow) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == sockaddr) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        int family = 0;
        ipaddr_t address = convert_sockaddr(sockaddr, family);
#ifndef SUPPORT_IPV6
        if (AF_INET6 == family) {
            ret = errorcode_t::not_supported;
            __leave2;
        }
#endif
        mask = (AF_INET6 == family) ? mask : mask % 0xffffffff;
        ipaddr_t subnet_mask = t_cidr_subnet_mask<ipaddr_t>(mask);
        ipaddr_t address_from = (address & subnet_mask);
        ipaddr_t address_to = (address & subnet_mask) | ~subnet_mask;

        ipaddress_rule_item_t item;
        item.mode = ipaddr_acl_t::cidr_addr;
        item.addr = address_to;
        item.allow = allow;

        critical_section_guard guard(_lock);
        ipaddress_rule_map_pib_t pib = _range_type_rule.insert(std::make_pair(address_from, item));
        if (false == pib.second) {
            ret = errorcode_t::already_exist;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t ipaddr_acl::add_rule(const char* addr_from, const char* addr_to, bool allow) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == addr_from || nullptr == addr_to) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        int family_from = 0;
        int family_to = 0;
        ipaddr_t address_from = convert_addr(addr_from, family_from);
        ipaddr_t address_to = convert_addr(addr_to, family_to);

#ifndef SUPPORT_IPV6
        if (AF_INET6 == family_from) {
            ret = errorcode_t::not_supported;
            __leave2;
        }
#endif
        if (family_from != family_to) {
            ret = errorcode_t::mismatch;
            __leave2;
        }
        if (address_from > address_to) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ipaddress_rule_item_t item;
        item.mode = ipaddr_acl_t::range_addr;
        item.addr = address_to;
        item.allow = allow;

        critical_section_guard guard(_lock);
        ipaddress_rule_map_pib_t pib = _range_type_rule.insert(std::make_pair(address_from, item));
        if (false == pib.second) {
            ret = errorcode_t::already_exist;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t ipaddr_acl::add_rule(const sockaddr_storage_t* sockaddr_from, const sockaddr_storage_t* sockaddr_to, bool allow) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == sockaddr_from || nullptr == sockaddr_to) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        int family_from = 0;
        int family_to = 0;
        ipaddr_t address_from = convert_sockaddr(sockaddr_from, family_from);
        ipaddr_t address_to = convert_sockaddr(sockaddr_to, family_to);

#ifndef SUPPORT_IPV6
        if (AF_INET6 == family_from) {
            ret = errorcode_t::not_supported;
            __leave2;
        }
#endif
        if (family_from != family_to) {
            ret = errorcode_t::mismatch;
            __leave2;
        }
        if (address_from > address_to) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ipaddress_rule_item_t item;
        item.mode = ipaddr_acl_t::range_addr;
        item.addr = address_to;
        item.allow = allow;

        critical_section_guard guard(_lock);
        ipaddress_rule_map_pib_t pib = _range_type_rule.insert(std::make_pair(address_from, item));
        if (false == pib.second) {
            ret = errorcode_t::already_exist;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t ipaddr_acl::clear() {
    return_t ret = errorcode_t::success;

    critical_section_guard guard(_lock);
    _range_type_rule.clear();
    return ret;
}

return_t ipaddr_acl::determine(const char* addr, bool& accept) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == addr) {
            ret = errorcode_t::invalid_parameter;
            accept = false;
            __leave2;
        }

        /* default action in black and white mode */
        if (ipaddr_acl_t::blacklist == _mode) {
            accept = true;
        } else { /* NETWORK_ACCESS_CONTROL_WHITELIST */
            accept = false;
        }

        int family = 0;
        ipaddr_t address = convert_addr(addr, family);
#ifndef SUPPORT_IPV6
        if (AF_INET6 == family) {
            ret = errorcode_t::not_supported;
            __leave2;
        }
#endif
        std::list<bool> result;

        {
            critical_section_guard guard(_lock);
            ipaddress_rule_map_t::iterator iter = _single_type_rule.find(address);
            if (_single_type_rule.end() != iter) {
                result.push_back(iter->second.allow);
            }
            for (const auto& pair : _range_type_rule) {
                const auto& begin = pair.first;
                const auto& item = pair.second;
                const ipaddr_t& end = pair.second.addr;

                if ((begin <= address) && (address <= end)) {
                    result.push_back(item.allow);
                }
                if (begin > address) {
                    break;
                }
            }
        }

        if (result.size()) {
            result.sort();
            result.unique();
            if (result.size() > 1) { /* both true and false */
                accept = false;
            } else {
                accept = result.front(); /* read allow */
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t ipaddr_acl::determine(const sockaddr_storage_t* sockaddr, bool& accept) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == sockaddr) {
            ret = errorcode_t::invalid_parameter;
            accept = false;
            __leave2;
        }

        /* default action in black and white mode */
        if (ipaddr_acl_t::blacklist == _mode) {
            accept = true;
        } else { /* NETWORK_ACCESS_CONTROL_WHITELIST */
            accept = false;
        }

        int family = 0;
        ipaddr_t address = convert_sockaddr(sockaddr, family);
#ifndef SUPPORT_IPV6
        if (AF_INET6 == family) {
            ret = errorcode_t::not_supported;
            __leave2;
        }
#endif
        std::list<bool> result;

        {
            critical_section_guard guard(_lock);
            ipaddress_rule_map_t::iterator iter = _single_type_rule.find(address);
            if (_single_type_rule.end() != iter) {
                result.push_back(iter->second.allow);
            }
            for (const auto& pair : _range_type_rule) {
                const auto& begin = pair.first;
                const auto& item = pair.second;
                const ipaddr_t& end = pair.second.addr;

                if ((begin <= address) && (address <= end)) {
                    result.push_back(item.allow);
                }
                if (begin > address) {
                    break;
                }
            }
        }

        if (result.size()) {
            result.sort();
            result.unique();
            if (result.size() > 1) { /* both true and false */
                accept = false;
            } else {
                accept = result.front(); /* read allow */
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

ipaddr_t ipaddr_acl::convert_addr(const char* addr, int& family) {
    ipaddr_t ret_value = 0;

    if (nullptr != addr) {
        char addr_buf[16];
        memset(addr_buf, 0, sizeof(addr_buf));
        const char* temp = strstr(addr, ":");
        if (nullptr == temp) {
            family = AF_INET;
            inet_pton(family, addr, (void*)&addr_buf);
            ret_value = ntoh32(*(uint32*)addr_buf);
        } else {
            family = AF_INET6;
            inet_pton(family, addr, (void*)&addr_buf);
#if defined __SIZEOF_INT128__
            ret_value = ntoh128(*(ipaddr_t*)addr_buf);
#else
            ret_value = ntoh32(*(ipaddr_t*)addr_buf);
#endif
        }
    }
    return ret_value;
}

ipaddr_t ipaddr_acl::convert_sockaddr(const sockaddr_storage_t* addr, int& family) {
    ipaddr_t ret_value = 0;

    if (nullptr != addr) {
        struct sockaddr_storage ss;
        memset(&ss, 0, sizeof(ss));
        family = addr->ss_family;
        if (AF_INET == addr->ss_family) {
            ((struct sockaddr_in*)&ss)->sin_addr = ((struct sockaddr_in*)addr)->sin_addr;
            ret_value = ntoh32(*(uint*)&((struct sockaddr_in*)&ss)->sin_addr);
        } else if (AF_INET6 == addr->ss_family) {
            ((struct sockaddr_in6*)&ss)->sin6_addr = ((struct sockaddr_in6*)addr)->sin6_addr;
#if defined __SIZEOF_INT128__
            ret_value = ntoh128(*(ipaddr_t*)&((struct sockaddr_in6*)&ss)->sin6_addr);
#else
            ret_value = ntoh32(*(ipaddr_t*)&((struct sockaddr_in6*)&ss)->sin6_addr);
#endif
        }
    }
    return ret_value;
}

}  // namespace net
}  // namespace hotplace
