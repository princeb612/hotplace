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

#include <hotplace/sdk/base/stream/vtprintf.hpp>
#include <hotplace/sdk/io/asn.1/asn1_encode.hpp>
#include <hotplace/sdk/io/asn.1/asn1_visitor.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_information_object.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_object.hpp>
#include <set>

namespace hotplace {
namespace io {

asn1_information_object::asn1_information_object() {}

asn1_information_object::~asn1_information_object() {}

void asn1_information_object::addref() { _shared.addref(); }

void asn1_information_object::release() { _shared.delref(); }

}  // namespace io
}  // namespace hotplace
