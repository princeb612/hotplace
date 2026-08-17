/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_information_object.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *
 */

#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_information_object.hpp>

namespace hotplace {
namespace io {

asn1_information_object::asn1_information_object() {}

asn1_information_object::~asn1_information_object() {}

void asn1_information_object::addref() { _shared.addref(); }

void asn1_information_object::release() { _shared.delref(); }

}  // namespace io
}  // namespace hotplace
