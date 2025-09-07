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
#include <sdk/net/tls/tls_container.hpp>

namespace hotplace {
namespace net {

class tls_extensions {
   public:
    tls_extensions();

    return_t read(tls_handshake *handshake, tls_direction_t dir, const byte_t *stream, size_t size, size_t &pos);
    return_t read(tls_handshake *handshake, tls_direction_t dir, const binary_t &bin);
    return_t write(tls_direction_t dir, binary_t &bin);

    /**
     * add
     *  case 1
     *          auto extension = new tls_extension_unknown(tls_ext_encrypt_then_mac, handshake);
     *          handshake->get_extensions().add(extension);
     *  case 2
     *          handshake->get_extensions().add(tls_ext_encrypt_then_mac, dir, handshake, nullptr);
     *  case 3
     *          handshake->get_extensions().add(tls_ext_ec_point_formats, dir, handshake, [](tls_extension* extension) -> return_t {
     *              (*(tls_extension_ec_point_formats*)extension).add("uncompressed");
     *              return success;
     *          });
     */
    return_t add(tls_extension *extension, bool upref = false);
    tls_extensions &add(uint16 type, tls_direction_t dir, tls_handshake *handshake, std::function<return_t(tls_extension *)> func = nullptr,
                        bool upref = false);
    tls_extensions &operator<<(tls_extension *extension);
    tls_extensions &operator<<(tls_extensions *extensions);
    return_t for_each(std::function<return_t(tls_extension *)> func);
    tls_extension *get(uint16 type, bool upref = false);
    tls_extension *getat(size_t index, bool upref = false);
    bool empty();
    size_t size();
    void clear();

   protected:
   private:
    critical_section _lock;
    t_tls_distinct_container<tls_extension *, uint16> _extensions;  // tls_ext_type_t
};

}  // namespace net
}  // namespace hotplace

#endif
