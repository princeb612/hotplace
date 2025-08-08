/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  RFC 7049 Concise Binary Object Representation (CBOR)
 *  RFC 8949 Concise Binary Object Representation (CBOR)
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_IO_CBOR_CBORSIMPLE__
#define __HOTPLACE_SDK_IO_CBOR_CBORSIMPLE__

#include <sdk/io/cbor/cbor_object.hpp>

namespace hotplace {
namespace io {

/**
 * @brief   cbor_simple
 */
class cbor_simple : public cbor_object {
   public:
    cbor_simple(uint8 value);

    cbor_simple_t simple_type();
    static cbor_simple_t is_kind_of(uint8 first);
    static cbor_simple_t is_kind_of_value(uint8 value);

   protected:
    virtual void represent(stream_t* s);
    virtual void represent(binary_t* b);

   private:
    cbor_simple_t _type;
    uint8 _value;
};

}  // namespace io
}  // namespace hotplace

#endif
