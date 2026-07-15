/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_notation_visitor.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_BASIC_ASN1NOTATIONVISOTOR__
#define __HOTPLACE_SDK_IO_ASN1_BASIC_ASN1NOTATIONVISOTOR__

#include <hotplace/sdk/io/asn.1/basic/asn1_visitor.hpp>

namespace hotplace {
namespace io {

class asn1_notation_visitor : public asn1_visitor {
   public:
    asn1_notation_visitor(stream_t* s, asn1_value* value = nullptr);
    virtual ~asn1_notation_visitor();

    virtual void visit(asn1_object* object);

   protected:
    stream_t* get_stream();

   private:
    stream_t* _s;
    asn1_value* _value;
};

}  // namespace io
}  // namespace hotplace

#endif
