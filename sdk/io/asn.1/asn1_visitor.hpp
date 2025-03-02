/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_VISOTOR__
#define __HOTPLACE_SDK_IO_ASN1_VISOTOR__

#include <sdk/base/basic/base16.hpp>
#include <sdk/base/basic/ieee754.hpp>
#include <sdk/base/basic/variant.hpp>
#include <sdk/base/system/endian.hpp>
#include <sdk/base/system/shared_instance.hpp>
#include <sdk/io/asn.1/types.hpp>
#include <sdk/io/basic/parser.hpp>

namespace hotplace {
namespace io {

class asn1_object;
class asn1_tag;

class asn1_visitor {
   public:
    virtual void visit(asn1_object* object) = 0;
};

class asn1_basic_encoding_visitor : public asn1_visitor {
   public:
    asn1_basic_encoding_visitor(binary_t* b);
    virtual void visit(asn1_object* object);

   protected:
    binary_t* get_binary();

   private:
    binary_t* _b;
};

class asn1_notation_visitor : public asn1_visitor {
   public:
    asn1_notation_visitor(stream_t* s);
    virtual void visit(asn1_object* object);

   protected:
    stream_t* get_stream();

   private:
    stream_t* _s;
};

}  // namespace io
}  // namespace hotplace

#endif
