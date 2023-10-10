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

#ifndef __HOTPLACE_SDK_IO_CBOR_CBORPUBLISHER__
#define __HOTPLACE_SDK_IO_CBOR_CBORPUBLISHER__

#include <deque>
#include <hotplace/sdk/base.hpp>
#include <hotplace/sdk/io/cbor/cbor_object.hpp>
#include <hotplace/sdk/io/stream/stream.hpp>

namespace hotplace {
namespace io {

/*
 * @brief concise, diagnostic
 * @example
 *      cbor_array* root = new cbor_array ();
 *      *root << new cbor_data (1) << new cbor_data (2) << new cbor_data (3);
 *
 *      cbor_publisher publisher;
 *      binary_t bin;
 *      basic_stream diagnostic;
 *
 *      publisher.publish (root, &diagnostic); // [1,2,3]
 *      publisher.publish (root, &bin);
 *
 *      std::string concise;
 *      base16_encode (bin, concise);   // base16 "83010203"
 */
class cbor_publisher {
   public:
    cbor_publisher();

    /*
     * concise
     */
    return_t publish(cbor_object* object, binary_t* b);
    /*
     * diagnostic
     */
    return_t publish(cbor_object* object, stream_t* s);
};

}  // namespace io
}  // namespace hotplace

#endif
