/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_IO_CBOR_CBORREADER__
#define __HOTPLACE_SDK_IO_CBOR_CBORREADER__

#include <hotplace/sdk/base.hpp>
#include <hotplace/sdk/io/cbor/cbor_object.hpp>
#include <hotplace/sdk/io/stream/stream.hpp>
#include <deque>

namespace hotplace {
namespace io {

struct _cbor_reader_context_t;
typedef struct _cbor_reader_context_t cbor_reader_context_t;

/**
 * @brief   parse
 * @example
 *          const char* input = "8301820203820405";
 *          cbor_reader_context_t* handle = nullptr;
 *          ansi_string bs;
 *          binary_t bin;
 *
 *          reader.open (&handle);
 *          reader.parse (handle, input);
 *          reader.publish (handle, &bs);   // diagnostic "[1,[2,3],[4,5]]"
 *          reader.publish (handle, &bin);  // encoded 0x8301820203820405
 *          reader.close (handle);
 *
 *          std::string concise;
 *          base16_encode (bin, concise);   // base16 "8301820203820405"
 */
class cbor_reader
{
public:
    cbor_reader ();

    /*
     * @brief   parse
     * @param   cbor_reader_context_t** handle [out]
     * @return  error code (see error.hpp)
     */
    return_t open (cbor_reader_context_t** handle);
    /*
     * @brief   parse
     * @param   cbor_reader_context_t* handle [in]
     * @return  error code (see error.hpp)
     */
    return_t close (cbor_reader_context_t* handle);
    /*
     * @brief   parse
     * @param   cbor_reader_context_t* handle [in]
     * @param   const char* expr [in] base16 encoded
     * @return  error code (see error.hpp)
     */
    return_t parse (cbor_reader_context_t* handle, const char* expr);
    /*
     * @brief   parse
     * @param   cbor_reader_context_t* handle [in]
     * @param   byte_t* const& data [in]
     * @param   size_t size [in]
     * @return  error code (see error.hpp)
     */
    return_t parse (cbor_reader_context_t* handle, const byte_t* data, size_t size);
    /*
     * @brief   parse
     * @param   cbor_reader_context_t* handle [in]
     * @param   const char* expr [in]
     * @return  error code (see error.hpp)
     */
    return_t parse (cbor_reader_context_t* handle, binary_t const& bin);

    /*
     * @brief   publish
     * @param   cbor_reader_context_t* handle [in]
     * @param   stream_t* stream [out] diagnostic
     * @return  error code (see error.hpp)
     */
    return_t publish (cbor_reader_context_t* handle, stream_t* stream);
    /*
     * @brief   publish
     * @param   cbor_reader_context_t* handle [in]
     * @param   binary_t* bin [out] cbor
     * @return  error code (see error.hpp)
     */
    return_t publish (cbor_reader_context_t* handle, binary_t* bin);
    /*
     * @brief   publish
     * @param   cbor_reader_context_t* handle [in]
     * @param   cbor_object** root [out]
     * @return  error code (see error.hpp)
     */
    return_t publish (cbor_reader_context_t* handle, cbor_object** root);

protected:
    return_t push (cbor_reader_context_t* handle, uint8 type, int128 data, uint32 flags);
    return_t push (cbor_reader_context_t* handle, uint8 type, const char* data, size_t size, uint32 flags);
    return_t push (cbor_reader_context_t* handle, uint8 type, const byte_t* data, size_t size, uint32 flags);
    return_t push (cbor_reader_context_t* handle, uint8 type, float data, size_t size);
    return_t push (cbor_reader_context_t* handle, uint8 type, double data, size_t size);

    return_t insert (cbor_reader_context_t* handle, cbor_object* objct);

    return_t pop (cbor_reader_context_t* handle, cbor_object* object);
    bool is_capacity_full (cbor_object* object);

private:
};

}
}  // namespace

#endif
