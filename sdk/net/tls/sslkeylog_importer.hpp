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

#ifndef __HOTPLACE_SDK_NET_TLS_SSLKEYLOGIMPORTER__
#define __HOTPLACE_SDK_NET_TLS_SSLKEYLOGIMPORTER__

#include <sdk/base/system/critical_section.hpp>
#include <sdk/crypto/basic/types.hpp>
#include <sdk/net/tls/tls_advisor.hpp>
#include <sdk/net/tls/types.hpp>

namespace hotplace {
namespace net {

class sslkeylog_importer {
   public:
    static sslkeylog_importer* get_instance();

    /**
     * @example
     *          auto sslkeylog = sslkeylog_importer::get_instance();
     *          sslkeylog->attach(&session);
     *          // TLS 1.3
     *          keylog << "SERVER_HANDSHAKE_TRAFFIC_SECRET RANDOM(64-letter) value";
     *          keylog << "CLIENT_HANDSHAKE_TRAFFIC_SECRET RANDOM(64-letter) value";
     *          keylog << "EXPORTER_SECRET RANDOM(64-letter) value";
     *          keylog << "SERVER_TRAFFIC_SECRET_0 RANDOM(64-letter) value";
     *          keylog << "CLIENT_TRAFFIC_SECRET_0 RANDOM(64-letter) value";
     *          // TLS 1.2
     *          keylog << "CLIENT_RANDOM RANDOM(64-letter) value";
     */
    sslkeylog_importer& operator<<(const std::string& secret);

    return_t attach(tls_session* session);
    void clear();

   protected:
    sslkeylog_importer();
    void load();

    return_t add(const std::string& secret);
    static void session_status_changed(tls_session* session, uint32 status);

    typedef std::map<tls_secret_t, binary_t> secret_map_t;
    typedef std::map<binary_t, secret_map_t> keylogs_t;
    keylogs_t _keylogs;

    critical_section _lock;
    static sslkeylog_importer _instance;
    std::map<std::string, tls_secret_t> _table;
    std::map<tls_secret_t, std::string> _rtable;
};

}  // namespace net
}  // namespace hotplace

#endif
