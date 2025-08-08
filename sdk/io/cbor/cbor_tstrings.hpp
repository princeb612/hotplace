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

#ifndef __HOTPLACE_SDK_IO_CBOR_CBORTSTRINGS__
#define __HOTPLACE_SDK_IO_CBOR_CBORTSTRINGS__

#include <sdk/io/cbor/cbor_object.hpp>

namespace hotplace {
namespace io {

class cbor_tstrings : public cbor_object {
    friend class cbor_concise_visitor;
    friend class cbor_diagnostic_visitor;

   public:
    cbor_tstrings();
    virtual ~cbor_tstrings();

    /*
     * @brief   add
     * @param   cbor_object* object [in]
     * @param   cbor_object* extra [inopt] ignored
     * @return  error code (see error.hpp)
     */
    virtual return_t join(cbor_object* object, cbor_object* extra = nullptr);
    cbor_tstrings& add(cbor_object* object, cbor_object* extra = nullptr);
    cbor_tstrings& add(const char* str);
    cbor_tstrings& operator<<(const char* str);

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
