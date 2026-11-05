/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_generalizedtime.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *
 */

#include <hotplace/sdk/io/asn.1/basic/semantic/builtin/types.hpp>

namespace hotplace {
namespace io {

asn1_generalizedtime::asn1_generalizedtime() : asn1_builtin_type(asn1_entity_generalizedtime) {}

asn1_generalizedtime::asn1_generalizedtime(const std::string& name) : asn1_builtin_type(name, asn1_entity_generalizedtime) {}

asn1_generalizedtime::asn1_generalizedtime(const std::string& name, const std::string& value) : asn1_builtin_type(name, asn1_entity_generalizedtime, value) {}

asn1_generalizedtime::~asn1_generalizedtime() {}

}  // namespace io
}  // namespace hotplace
