/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_HTTP_HPACK_HPACKENCODER__
#define __HOTPLACE_SDK_NET_HTTP_HPACK_HPACKENCODER__

#include <hotplace/sdk/net/http/compression/http_header_compression.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   RFC 7541 HPACK: Header Compression for HTTP/2
 */
class hpack_encoder : public http_header_compression {
   public:
    hpack_encoder();

    /**
     * @brief   encode (header compression)
     * @param   http_dynamic_table* dyntable [in] dynamic table
     * @param   binary_t& target [out]
     * @param   const std::string& name [in]
     * @param   const std::string& value [in]
     * @param   uint32 flags [inopt] see http_header_compression_flag_t
     * @return  error code (see error.hpp)
     */
    virtual return_t encode(http_dynamic_table* dyntable, binary_t& target, const std::string& name, const std::string& value, uint32 flags = 0);
    /**
     * @brief   decode (header compression)
     * @param   http_dynamic_table* dyntable [in] dynamic table
     * @param   const byte_t* source [in]
     * @param   size_t size [in]
     * @param   size_t& pos [in]
     * @param   std::string& name [in]
     * @param   std::string& value [in]
     * @return  error code (see error.hpp)
     * @sample
     *          pos = 0;
     *          while (pos < streamsize) {
     *              encoder.decode(dyntable, stream, streamsize, pos, name, value, flags);
     *          }
     *          // keep the index until the decoder process is finished
     *          // insert into dynamic table
     *          dyntable->commit();
     */
    virtual return_t decode(http_dynamic_table* dyntable, const byte_t* source, size_t size, size_t& pos, std::string& name, std::string& value);

    /**
     * @brief   encode (header compression)
     * @param   http_dynamic_table* dyntable [in] dynamic table
     * @param   binary_t& target [out]
     * @param   const std::string& name [in]
     * @param   const std::string& value [in]
     * @param   uint32 flags [inopt] see http_header_compression_flag_t
     */
    hpack_encoder& encode_header(http_dynamic_table* dyntable, binary_t& target, const std::string& name, const std::string& value, uint32 flags = 0);
    /**
     * @brief   decode (header compression)
     * @param   http_dynamic_table* dyntable [in] dynamic table
     * @param   const byte_t* source [in]
     * @param   size_t size [in]
     * @param   size_t& pos [in]
     * @param   std::string& name [in]
     * @param   std::string& value [in]
     */
    hpack_encoder& decode_header(http_dynamic_table* dyntable, const byte_t* source, size_t size, size_t& pos, std::string& name, std::string& value);
    /**
     * @brief   dynamic table size
     * @param   http_dynamic_table* dyntable [in]
     * @param   binary_t& target
     * @param   uint8 maxsize
     * @return  error code (see error.hpp)
     * @remarks
     *          RFC 7541 6.3.  Dynamic Table Size Update
     *          RFC 9204 4.3.1.  Set Dynamic Table Capacity
     */
    virtual return_t set_capacity(http_dynamic_table* dyntable, binary_t& target, uint8 maxsize);

   protected:
    /**
     * @brief   index
     * @param   binary_t& target [out]
     * @param   size_t index [in]
     */
    hpack_encoder& encode_index(binary_t& target, size_t index);
    /**
     * @bried   indexed name
     * @param   binary_t& target [out]
     * @param   uint32 flags [in]
     * @param   size_t index [in]
     * @param   const char* value [in]
     */
    hpack_encoder& encode_indexed_name(binary_t& target, uint32 flags, size_t index, const char* value);
    /**
     * @bried   indexed name
     * @param   binary_t& target [out]
     * @param   uint32 flags [in]
     * @param   size_t index [in]
     * @param   const char* value [in]
     * @param   size_t size [in]
     */
    hpack_encoder& encode_indexed_name(binary_t& target, uint32 flags, size_t index, const char* value, size_t size);
    /**
     * @bried   indexed name
     * @param   binary_t& target [out]
     * @param   uint32 flags [in]
     * @param   size_t index [in]
     * @param   const std::string& value [in]
     */
    hpack_encoder& encode_indexed_name(binary_t& target, uint32 flags, size_t index, const std::string& value);
    /**
     * @brief   name value
     * @param   binary_t& target [out]
     * @param   uint32 flags [in]
     * @param   const char* name [in]
     * @param   const char* value [in]
     */
    hpack_encoder& encode_name_value(binary_t& target, uint32 flags, const char* name, const char* value);
    /**
     * @brief   name value
     * @param   binary_t& target [out]
     * @param   uint32 flags [in]
     * @param   const char* name [in]
     * @param   size_t namelen [in]
     * @param   const char* value [in]
     * @param   size_t valuelen [in]
     */
    hpack_encoder& encode_name_value(binary_t& target, uint32 flags, const char* name, size_t namelen, const char* value, size_t valuelen);
    /**
     * @brief   name value
     * @param   binary_t& target [out]
     * @param   uint32 flags [in]
     * @param   const std::string& name [in]
     * @param   const std::string& value [in]
     */
    hpack_encoder& encode_name_value(binary_t& target, uint32 flags, const std::string& name, const std::string& value);
};

}  // namespace net
}  // namespace hotplace

#endif
