/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_utf8string.cpp
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

asn1_utf8string::asn1_utf8string() : asn1_builtin_type(asn1_entity_utf8string) {}

asn1_utf8string::asn1_utf8string(const std::string& name) : asn1_builtin_type(name, asn1_entity_utf8string) {}

asn1_utf8string::asn1_utf8string(const std::string& name, const std::string& value) : asn1_builtin_type(name, asn1_entity_utf8string, value) {}

asn1_utf8string::~asn1_utf8string() {}

}  // namespace io
}  // namespace hotplace
