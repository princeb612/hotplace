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

#ifndef __HOTPLACE_SDK_NET_TLS1_EXTENSION__
#define __HOTPLACE_SDK_NET_TLS1_EXTENSION__

#include <sdk/base/system/critical_section.hpp>
#include <sdk/base/system/types.hpp>
#include <sdk/crypto/basic/crypto_key.hpp>
#include <sdk/crypto/basic/types.hpp>
#include <sdk/crypto/crypto/types.hpp>
#include <sdk/net/tls1/types.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   TLS extension
 */
class tls_extension {
   public:
    tls_extension(tls_session* session);
    tls_extension(const tls_extension& rhs);
    tls_extension(uint16 type, tls_session* session);
    ~tls_extension();

    virtual return_t read(const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream = nullptr);
    virtual return_t read_header(const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream = nullptr);
    virtual return_t read_data(const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream = nullptr);
    virtual return_t write(binary_t& bin, stream_t* debugstream = nullptr);

    tls_session* get_session();
    void set_type(uint16 type);
    uint16 get_type();
    const range_t& get_header_range();
    uint16 get_length();
    size_t get_extsize();
    size_t endpos_extension();

    void addref();
    void release();

   protected:
    t_shared_reference<tls_extension> _shared;

    tls_session* _session;
    uint16 _type;
    range_t _header_range;  // range(header)
    uint16 _payload_len;    // size(payload)
    size_t _size;           // size(header) + size(payload)
};

}  // namespace net
}  // namespace hotplace

#endif
