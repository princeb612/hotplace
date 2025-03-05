/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 */

#ifndef __HOTPLACE_SDK_NET_TLS_TLS_EXTENSION_TLSEXTENSIONS__
#define __HOTPLACE_SDK_NET_TLS_TLS_EXTENSION_TLSEXTENSIONS__

#include <sdk/net/tls/tls/extension/tls_extension.hpp>

namespace hotplace {
namespace net {

class tls_extensions {
   public:
    tls_extensions();
    ~tls_extensions();

    return_t read(tls_hs_type_t hstype, tls_session *session, tls_direction_t dir, const byte_t *stream, size_t size, size_t &pos);
    return_t read(tls_hs_type_t hstype, tls_session *session, tls_direction_t dir, const binary_t &bin);

    return_t write(binary_t &bin);

    return_t add(tls_extension *extension, bool upref = false);
    tls_extensions &operator<<(tls_extension *extension);

    void for_each(std::function<void(tls_extension *)> func);

    tls_extension *get(uint16 type, bool upref = false);
    tls_extension *getat(size_t index, bool upref = false);

    size_t size();

    void clear();

   protected:
   private:
    critical_section _lock;
    std::map<uint16, tls_extension *> _dictionary;  // tls1_ext_type_t
    std::vector<tls_extension *> _extensions;       // ordered
};

}  // namespace net
}  // namespace hotplace

#endif
