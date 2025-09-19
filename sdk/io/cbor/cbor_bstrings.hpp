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

#ifndef __HOTPLACE_SDK_IO_CBOR_CBORBSTRINGS__
#define __HOTPLACE_SDK_IO_CBOR_CBORBSTRINGS__

#include <hotplace/sdk/io/cbor/cbor_object.hpp>

namespace hotplace {
namespace io {

class cbor_bstrings : public cbor_object {
    friend class cbor_concise_visitor;
    friend class cbor_diagnostic_visitor;

   public:
    cbor_bstrings();
    virtual ~cbor_bstrings();

    /*
     * @brief   add
     * @param   cbor_object* object [in]
     * @param   cbor_object* extra [inopt] ignored
     * @return  error code (see error.hpp)
     */
    virtual return_t join(cbor_object* object, cbor_object* extra = nullptr);
    cbor_bstrings& add(cbor_object* object, cbor_object* extra = nullptr);
    cbor_bstrings& add(const byte_t* bstr, size_t size);
    cbor_bstrings& operator<<(binary_t bin);

    virtual size_t size();

    virtual int addref();
    virtual int release();

   protected:
    virtual void represent(stream_t* s);
    virtual void represent(binary_t* b);

   private:
    std::list<cbor_data*> _array;
};

}  // namespace io
}  // namespace hotplace

#endif
