/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_HTTP_HTTP2_HPACK__
#define __HOTPLACE_SDK_NET_HTTP_HTTP2_HPACK__

#include <sdk/net/http/http2/http_header_compression.hpp>  // http_header_compression
#include <sdk/net/http/types.hpp>

namespace hotplace {
namespace net {

// RFC 7541 HPACK: Header Compression for HTTP/2

class hpack_encoder;
class hpack_session;

template <typename DYNAMIC_T, typename ENCODER_T>
class http_header_compression_stream;

typedef http_header_compression_stream<hpack_session, hpack_encoder> hpack_stream;

/**
 * @brief   HPACK
 * @sample
 *          http_header_compression_stream hp;
 *          hpack_session session;
 *          hp
 *              .set_encoder(encoder)
 *              .set_session(&session)
 *              .set_encode_flags(hpack_indexing | hpack_huffman)
 *              .encode_header(name1, value1)
 *              .encode_header(name2, value2);
 *          // do something dump_memory(hp.get_binary(), &bs);
 *          hp.get_binary().clear();
 */
template <typename DYNAMIC_T, typename ENCODER_T>
class http_header_compression_stream {
   public:
    http_header_compression_stream() : _session(nullptr), _flags(hpack_indexing | hpack_huffman), _autocommit(true) {}
    ~http_header_compression_stream() {}

    /**
     * @brief   set
     * @remarks reduce repetition of the following values : session, binary, flags
     */
    http_header_compression_stream<DYNAMIC_T, ENCODER_T>& set_session(DYNAMIC_T* session) {
        _session = session;
        return *this;
    }

    /**
     * @brief   get
     */
    DYNAMIC_T* get_session() { return _session; }

    /**
     * @brief   set flags for encoding
     */
    http_header_compression_stream<DYNAMIC_T, ENCODER_T>& set_encode_flags(uint32 flags) {
        _flags = flags;
        return *this;
    }
    /**
     * @brief   encode
     * @param   const std::string& name [in]
     * @param   const std::string& value [in]
     * @param   uint32 flags [inopt] if zero, follows set_encode_flags
     * @sample
     *          hpack_stream hp;
     *          hpack_session session;
     *          hp
     *              .set_encoder(encoder)
     *              .set_session(&session)
     *              .set_encode_flags(hpack_indexing | hpack_huffman)
     *              .encode_header(name1, value1)
     *              .encode_header(name2, value2);
     *              .encode_header("content-length", "123", hpack_wo_indexing | hpack_huffman);
     */
    http_header_compression_stream<DYNAMIC_T, ENCODER_T>& encode_header(const std::string& name, const std::string& value, uint32 flags = 0) {
        if (_session) {
            ENCODER_T encoder;
            encoder.encode_header(_session, _bin, name, value, flags ? flags : _flags);
            if (_autocommit) {
                commit();
            }
        }
        return *this;
    }

    /**
     * @brief   decode
     */
    http_header_compression_stream<DYNAMIC_T, ENCODER_T>& decode_header(const byte_t* source, size_t size, size_t& pos, std::string& name, std::string& value) {
        if (_session) {
            ENCODER_T encoder;
            encoder.decode_header(_session, source, size, pos, name, value);
            if (_autocommit) {
                commit();
            }
        }
        return *this;
    }

    /**
     * @brief   encoded data
     */
    binary_t& get_binary() { return _bin; }

    http_header_compression_stream<DYNAMIC_T, ENCODER_T>& autocommit(bool enable = true) {
        _autocommit = enable;
        return *this;
    }
    http_header_compression_stream<DYNAMIC_T, ENCODER_T>& commit() {
        if (_session) {
            _session->commit();
        }
        return *this;
    }

   private:
    DYNAMIC_T* _session;
    uint32 _flags;
    binary_t _bin;
    bool _autocommit;
};

/**
 * @brief   RFC 7541 HPACK
 * @remarks
 *          t_shared_instance<hpack_encoder> _hpack;
 *          // RFC 7541 Appendix B. Huffman Code
 *          // RFC 7541 Appendix A.  Static Table Definition
 *          hpack_instance.make_share(new hpack_encoder); // load resources here
 *
 *              // thread #1 connection #1
 *              hpack_session session;
 *              (*hpack_instance).encode_header(&session, ...); // handle dynamic table #1
 *
 *              // thread #2 connection #2
 *              hpack_session session;
 *              (*hpack_instance).encode_header(&session, ...); // handle dynamic table #2
 *
 */
class hpack_encoder : public http_header_compression {
   public:
    hpack_encoder();

    /**
     * @brief   encode (header compression)
     * @param   http_dynamic_table* session [in] dynamic table
     * @param   binary_t& target [out]
     * @param   const std::string& name [in]
     * @param   const std::string& value [in]
     * @param   uint32 flags [inopt] see http_header_compression_flag_t
     * @return  error code (see error.hpp)
     */
    virtual return_t encode(http_dynamic_table* session, binary_t& target, const std::string& name, const std::string& value, uint32 flags = 0);
    /**
     * @brief   decode (header compression)
     * @param   http_dynamic_table* session [in] dynamic table
     * @param   const byte_t* source [in]
     * @param   size_t size [in]
     * @param   size_t& pos [in]
     * @param   std::string& name [in]
     * @param   std::string& value [in]
     * @return  error code (see error.hpp)
     * @sample
     *          pos = 0;
     *          while (pos < streamsize) {
     *              encoder.decode(session, stream, streamsize, pos, name, value, flags);
     *          }
     *          // keep the index until the decoder process is finished
     *          // insert info dynamic table
     *          session.commit();
     */
    virtual return_t decode(http_dynamic_table* session, const byte_t* source, size_t size, size_t& pos, std::string& name, std::string& value);

    /**
     * @brief   encode (header compression)
     * @param   http_dynamic_table* session [in] dynamic table
     * @param   binary_t& target [out]
     * @param   const std::string& name [in]
     * @param   const std::string& value [in]
     * @param   uint32 flags [inopt] see http_header_compression_flag_t
     * @sample
     *          pos = 0;
     *          while (pos < target.size()) {
     *              encoder.decode(session, &target[0], target.size(), pos, name, value, flags);
     *          }
     *          // keep the index until the decoder process is finished
     *          // insert into dynamic table
     *          session.commit();
     */
    hpack_encoder& encode_header(http_dynamic_table* session, binary_t& target, const std::string& name, const std::string& value, uint32 flags = 0);
    /**
     * @brief   decode (header compression)
     * @param   http_dynamic_table* session [in] dynamic table
     * @param   const byte_t* source [in]
     * @param   size_t size [in]
     * @param   size_t& pos [in]
     * @param   std::string& name [in]
     * @param   std::string& value [in]
     */
    hpack_encoder& decode_header(http_dynamic_table* session, const byte_t* source, size_t size, size_t& pos, std::string& name, std::string& value);

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

/**
 * @brief   separate dynamic table per session
 * @sa      hpack_encoder
 */
class hpack_session : public http_dynamic_table {
   public:
    hpack_session();
    /**
     * @brief   HPACK query function
     * @param   int cmd [in] see header_compression_cmd_t
     * @param   void* req [in]
     * @param   size_t reqsize [in]
     * @param   void* resp [out]
     * @param   size_t& respsize [inout]
     * @return  error code (see error.hpp)
     */
    virtual return_t query(int cmd, void* req, size_t reqsize, void* resp, size_t& respsize);
};

}  // namespace net
}  // namespace hotplace

#endif
