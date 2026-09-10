/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_namednumberlist.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_BASIC_SEMANTIC_ASN1NAMEDNUMBERLIST__
#define __HOTPLACE_SDK_IO_ASN1_BASIC_SEMANTIC_ASN1NAMEDNUMBERLIST__

#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_type.hpp>
#include <map>

namespace hotplace {
namespace io {

// sketch - simple and intermediate role
//   asn1_integer << asn1_namednumberlist
//   asn1_bitstring << asn1_namednumberlist
//   asn1_enum << asn1_namednumberlist
class asn1_namednumberlist : public asn1_type {
    friend class asn1_integer;
    friend class asn1_bitstring;
    friend class asn1_enum;

   public:
    asn1_namednumberlist() : asn1_type(asn1_entity_namednumberlist) {}
    ~asn1_namednumberlist() {}

    asn1_namednumberlist& add(const std::string& name, asn1_native_int_t value) {
        _container.emplace(value, name);
        return *this;
    }
    asn1_namednumberlist& add(asn1_namednumberlist& nml) {
        _container.insert(nml._container.begin(), nml._container.end());
        return *this;
    }
    void clear() { _container.clear(); }

   private:
    std::map<asn1_native_int_t, std::string> _container;
};

}  // namespace io
}  // namespace hotplace

#endif
