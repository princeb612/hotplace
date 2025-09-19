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

#ifndef __HOTPLACE_SDK_NET_TLS_TLS_EXTENSION_TLSEXTENSION__
#define __HOTPLACE_SDK_NET_TLS_TLS_EXTENSION_TLSEXTENSION__

#include <hotplace/sdk/base/system/critical_section.hpp>
#include <hotplace/sdk/base/system/types.hpp>
#include <hotplace/sdk/crypto/basic/crypto_key.hpp>
#include <hotplace/sdk/crypto/basic/types.hpp>
#include <hotplace/sdk/net/tls/tls/types.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   TLS extension
 */
class tls_extension {
   public:
    tls_extension(tls_handshake* hs);
    tls_extension(const tls_extension& rhs);
    tls_extension(uint16 type, tls_handshake* hs);
    virtual ~tls_extension();

    static tls_extension* read(tls_handshake* handshake, tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);

    virtual return_t read(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t write(tls_direction_t dir, binary_t& bin);

    tls_handshake* get_handshake();
    void set_type(uint16 type);
    uint16 get_type();
    const range_t& get_header_range();
    size_t offsetof_header();
    size_t offsetof_body();
    uint16 get_body_size();
    size_t get_extsize();
    size_t endpos_extension();

    void addref();
    void release();

   protected:
    virtual return_t do_preprocess(tls_direction_t dir);
    virtual return_t do_postprocess(tls_direction_t dir);
    virtual return_t do_read_header(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write_header(tls_direction_t dir, binary_t& bin, const binary_t& body);
    virtual return_t do_write_body(tls_direction_t dir, binary_t& bin);

   private:
    t_shared_reference<tls_extension> _shared;

    tls_handshake* _hs;
    uint16 _type;
    range_t _header_range;  // range(header)
    uint16 _bodysize;       // size(payload)
    size_t _size;           // size(header) + size(payload)
};

}  // namespace net
}  // namespace hotplace

#endif
