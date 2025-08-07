/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_HTTP_HTTPHEADERCOMPRESSIONSTREAM__
#define __HOTPLACE_SDK_NET_HTTP_HTTPHEADERCOMPRESSIONSTREAM__

#include <sdk/net/http/http2/hpack_dynamic_table.hpp>
#include <sdk/net/http/http2/hpack_encoder.hpp>
#include <sdk/net/http/http3/qpack_dynamic_table.hpp>
#include <sdk/net/http/http3/qpack_encoder.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   HPACK/QPACK encoding/decoding
 * @sample
 *          // HPACK encoding
 *          {
 *              hpack_stream hp;
 *              hpack_dynamic_table session_encoder;
 *              hp
 *                  .set_session(&session_encoder)
 *                  .set_encode_flags(hpack_indexing | hpack_huffman)
 *                  .begin()
 *                  .encode_header(name1, value1)
 *                  .encode_header(name2, value2);
 *              _logger->dump(hp.get_binary());
 *          }
 *          // QPACK encoding
 *          {
 *              qpack_stream qp;
 *              qpack_dynamic_table session_encoder;
 *              qp
 *                  .set_session(&session_encoder)
 *                  .set_encode_flags(qpack_indexing | qpack_huffman)
 *                  .begin()
 *                  .encode_header(name1, value1)
 *                  .encode_header(name2, value2);
 *              _logger->dump(hp.get_binary());
 *          }
 *          // HPACK decoding
 *          {
 *              hpack_stream hp;
 *              hpack_dynamic_table session_decoder;
 *              size_t pos = 0;
 *              hp.set_session(session_decoder);
 *              while (pos < streamsize) {
 *                  hp.decode_header(stream, streamsize, pos, name, value);
 *                  // do something
 *              }
 *              // keep the index until the decoder process is finished
 *              // insert into dynamic table
 *              hp.commit();
 *          }
 *          // QPACK decoding
 *          {
 *              qpack_stream qp;
 *              qpack_dynamic_table session_decoder;
 *              size_t pos = 0;
 *              qp.set_session(session_decoder);
 *              while (pos < streamsize) {
 *                  qp.decode_header(stream, streamsize, pos, name, value);
 *                  // do something
 *              }
 *              // keep the index until the decoder process is finished
 *              // insert into dynamic table
 *              qp.commit();
 *          }
 */
template <typename DYNAMIC_T, typename ENCODER_T>
class http_header_compression_stream {
   public:
    http_header_compression_stream() : _session(nullptr), _flags(hpack_indexing | hpack_huffman), _autocommit(false) {}
    ~http_header_compression_stream() {}

    /**
     * @brief   set
     * @param   DYNAMIC_T* session [in]
     * @remarks reduce repetition of the following values : session, binary, flags
     */
    http_header_compression_stream<DYNAMIC_T, ENCODER_T>& set_session(DYNAMIC_T* session) {
        _session = session;
        return *this;
    }

    /**
     * @brief   get
     * @param   uint32 flags [in]
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
     *          hpack_dynamic_table session;
     *          hp
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
        }
        return *this;
    }

    /**
     * @brief   decode
     * @param   const byte_t* source [in]
     * @param   size_t size [in]
     * @param   size_t& pos [inout]
     * @param   std::string& name [out]
     * @param   std::string& value [out]
     * @sample
     *          pos = 0;
     *          hp.set_session(session);
     *          while (pos < bin.size()) {
     *              hp.decode_header(stream, streamsize, pos, name, value);
     *              // do something
     *          }
     *          // keep the index until the decoder process is finished
     *          // insert into dynamic table
     *          hp.commit();
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

    http_header_compression_stream<DYNAMIC_T, ENCODER_T>& autocommit(bool enable = true) {
        _autocommit = enable;
        return *this;
    }

    http_header_compression_stream<DYNAMIC_T, ENCODER_T>& begin() {
        _bin.clear();
        return *this;
    }
    http_header_compression_stream<DYNAMIC_T, ENCODER_T>& commit() {
        if (_session) {
            _session->commit();
        }
        return *this;
    }

    /**
     * @brief   encoded data
     */
    binary_t& get_binary() { return _bin; }

   private:
    DYNAMIC_T* _session;
    uint32 _flags;
    binary_t _bin;
    bool _autocommit;
};

typedef http_header_compression_stream<hpack_dynamic_table, hpack_encoder> hpack_stream;
typedef http_header_compression_stream<qpack_dynamic_table, qpack_encoder> qpack_stream;

}  // namespace net
}  // namespace hotplace

#endif
