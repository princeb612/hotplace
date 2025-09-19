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

#ifndef __HOTPLACE_SDK_IO_CBOR_CBORDATA__
#define __HOTPLACE_SDK_IO_CBOR_CBORDATA__

#include <hotplace/sdk/base/basic/ieee754.hpp>
#include <hotplace/sdk/io/cbor/cbor_object.hpp>

namespace hotplace {
namespace io {

class cbor_data : public cbor_object {
    friend class cbor_pair;
    friend class cbor_bstrings;
    friend class cbor_tstrings;
    friend class cbor_concise_visitor;
    friend class cbor_diagnostic_visitor;

   public:
    cbor_data();
    cbor_data(bool value);
    cbor_data(int8 value);
    cbor_data(int16 value);
    cbor_data(int32 value);
    cbor_data(int64 value);
#if defined __SIZEOF_INT128__
    cbor_data(int128 value);
#endif
    cbor_data(const byte_t* bstr, size_t size);
    cbor_data(const binary_t& bin);
    cbor_data(const char* tstr);
    cbor_data(const char* tstr, size_t length);
    cbor_data(const std::string& bin);
    cbor_data(const fp16_t& value);
    cbor_data(float value);
    cbor_data(double value);
    cbor_data(const variant_t& vt);
    cbor_data(variant_t&& vt);
    cbor_data(const variant& vt);
    cbor_data(variant&& vt);
    virtual ~cbor_data();

    variant& data();

   protected:
    virtual void represent(stream_t* s);
    virtual void represent(binary_t* b);

   private:
    variant _vt;
};

}  // namespace io
}  // namespace hotplace

#endif
