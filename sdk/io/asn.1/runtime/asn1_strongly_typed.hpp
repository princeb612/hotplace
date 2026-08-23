/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_strongly_typed.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_RUNTIME_ASN1STRONGTYPED__
#define __HOTPLACE_SDK_IO_ASN1_RUNTIME_ASN1STRONGTYPED__

#include <hotplace/sdk/io/asn.1/basic/semantic/types.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_bytestream.hpp>

namespace hotplace {
namespace io {

class asn1_strongly_typed {
    friend class asn1_runtime;

   public:
    asn1_strongly_typed();
    ~asn1_strongly_typed();

    return_t read(asn1_runtime* target, const std::string& name, const byte_t* stream, size_t size, size_t& pos);

   protected:
    return_t read_node(asn1_bytestream::TLV_node* node, asn1_object* object);

   private:
};

}  // namespace io
}  // namespace hotplace

#endif
