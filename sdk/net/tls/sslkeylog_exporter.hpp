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

#ifndef __HOTPLACE_SDK_NET_TLS_SSLKEYLOGEXPORTER__
#define __HOTPLACE_SDK_NET_TLS_SSLKEYLOGEXPORTER__

#include <sdk/base/system/critical_section.hpp>
#include <sdk/crypto/basic/types.hpp>
#include <sdk/net/tls/tls_advisor.hpp>
#include <sdk/net/tls/types.hpp>

namespace hotplace {
namespace net {

/**
 * @sample
 *          auto sslkeylog = sslkeylog_exporter::get_instance();
 *          auto lambda = [&](const char* line) -> void { _logger->writeln(line); };
 *          sslkeylog->set(lambda);
 */
class sslkeylog_exporter {
    friend class tls_protection;

   public:
    static sslkeylog_exporter* get_instance();

    sslkeylog_exporter& set(std::function<void(const char*)> func);
    /**
     * SSL_CTX_set_keylog_callback
     */
    void log(const char* line);

   protected:
    sslkeylog_exporter();

    /**
     * tls_protection key calcuration
     */
    return_t log(tls_session* session, tls_secret_t secret);

    static sslkeylog_exporter _instance;
    std::function<void(const char*)> _keylog_hook;
};

}  // namespace net
}  // namespace hotplace

#endif
