/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_BASIC_IPADDRACL__
#define __HOTPLACE_SDK_NET_BASIC_IPADDRACL__

#include <map>
#include <sdk/base/system/critical_section.hpp>
#include <sdk/net/basic/types.hpp>

namespace hotplace {
namespace net {

#if defined __SIZEOF_INT128__
#ifndef SUPPORT_IPV6
#define SUPPORT_IPV6
#endif
typedef uint128 ipaddr_t;
#else
typedef uint32 ipaddr_t;
#endif

/**
 * @brief cidr mask
 * @example
 *          ipaddr_acl acl;
 *          basic_stream stream;
 *          const char* address = "3ffe:ffff:0:f101::1";
 *          int family = 0;
 *          ipaddr_t ipv6 = acl.convert_addr (address, family);
 *          stream.printf("%032I128x\n", ipv6);
 *
 *          ipaddr_t mask = 0;
 *          uint cidr = 0;
 *          uint i = 0;
 *          for (i = 0; i <= 128; i++)
 *          {
 *              mask = t_cidr_subnet_mask<ipaddr_t> (i);
 *              stream.printf("%s/%d %032I128x & %032I128x => %032I128x ~ %032I128x\n",
 *                            address, i, ipv6, mask, ipv6 & mask, (ipv6 & mask)|~mask);
 *          }
 *          printf(stream.c_str());
 *
 *          //    ...
 *          //    3ffe:ffff:0:f101::1/64
 *          //    3ffeffff0000f1010000000000000001 & ffffffffffffffff0000000000000000
 *          // => 3ffeffff0000f1010000000000000000 ~ 3ffeffff0000f101ffffffffffffffff
 *          //    ...
 */
template <typename T>
T t_cidr_subnet_mask(uint cidr) {
    T ret = 0;
    uint i = 0;

    uint adj = ((sizeof(T) << 3));

    if (cidr <= adj) {
        T one = 1;
        for (i = 0; i < cidr; i++) {
            ret |= (one << (adj - 1 - i));
        }
    }

    return ret;
}

enum ipaddr_acl_t {
    blacklist = (1 << 0),  // prohibit only deny list
    whitelist = (1 << 1),  // accept only allow list

    single_addr = 0,
    cidr_addr = 1,
    range_addr = 2,
};

/**
 * @brief network access control
 * @remarks
 * @example
 *          bool check = true;
 *          ipaddr_acl ac;
 *
 *          ac.add_rule("10.20.15.25", true);
 *          ac.add_rule("10.20.14.25", false);
 *          ac.add_rule("10.20.13.25", 24, false);
 *          ac.add_rule("10.20.1.25", "10.20.2.10", false);
 *
 *          ac.setmode(ipaddr_acl_t::whitelist);
 *          ac.determine("10.20.15.25", check); // true
 *          ac.determine("10.20.14.25", check); // false
 *          ac.determine("10.20.13.25", check); // false
 *          ac.determine("10.21.13.25", check); // false
 *          ac.determine("10.20.2.11",  check); // false
 *
 *          ac.setmode(ipaddr_acl_t::blacklist);
 *          ac.determine("10.20.15.25", check); // true
 *          ac.determine("10.20.14.25", check); // false
 *          ac.determine("10.20.13.25", check); // false
 *          ac.determine("10.21.13.25", check); // true
 *          ac.determine("10.20.2.11",  check); // true
 */
class ipaddr_acl {
   public:
    ipaddr_acl();
    ipaddr_acl(ipaddr_acl& obj);
    ~ipaddr_acl();

    /**
     * @brief white list, black list
     * @remarks basically runs ipaddr_acl_t::blacklist mode
     */
    return_t setmode(int mode);

    /**
     * @brief single address or cidr
     * @param   const char*             addr        [IN] single address (1.2.3.4) or cidr (1.2.3.4/24) is possible.
     *                                                   1.2.3.4/  errorcode_t::invalid_parameter
     *                                                   1.2.3.4/0 possible
     * @param   bool                    allow       [IN]
     */
    return_t add_rule(const char* addr, bool allow);
    /**
     * @brief single address
     * @param   const sockaddr_storage_t* sockaddr  [IN]
     * @param   bool                    allow       [IN]
     */
    return_t add_rule(const sockaddr_storage_t* sockaddr, bool allow);
    /**
     * @brief cidr
     */
    return_t add_rule(const char* addr, int mask, bool allow);
    return_t add_rule(const sockaddr_storage_t* sockaddr, int mask, bool allow);

    /**
     * @brief range
     */
    return_t add_rule(const char* addr_from, const char* addr_to, bool allow);
    return_t add_rule(const sockaddr_storage_t* sockaddr_from, const sockaddr_storage_t* sockaddr_to, bool allow);
    /**
     * @brief clear
     */
    return_t clear();

    /**
     * @brief determine
     */
    return_t determine(const char* addr, bool& accept);
    return_t determine(const sockaddr_storage_t* sockaddr, bool& accept);

    /**
     * @brief return host byte ordered
     */
    ipaddr_t convert_addr(const char* addr, int& family);
    ipaddr_t convert_sockaddr(const sockaddr_storage_t* addr, int& family);

   protected:
    int _mode;

    typedef struct _IPADDRESS_RULE_ITEM {
        int mode;  // 0 single 1 cidr 2 range
        ipaddr_t addr;
        bool allow;  // allow/deny
    } ipaddress_rule_item_t;
    typedef std::map<ipaddr_t, ipaddress_rule_item_t> ipaddress_rule_map_t;
    typedef std::pair<ipaddress_rule_map_t::iterator, bool> ipaddress_rule_map_pib_t;

    critical_section _lock;
    ipaddress_rule_map_t _single_type_rule;  // 0 single
    ipaddress_rule_map_t _range_type_rule;   // 1 cidr, 2 range
};

}  // namespace net
}  // namespace hotplace

#endif
