/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   trial_tls_client_socket.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *      insecure simple implementation to understand TLS
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_NET_BASIC_TRIAL_TRIALTLSCLIENTSOCKET__
#define __HOTPLACE_SDK_NET_BASIC_TRIAL_TRIALTLSCLIENTSOCKET__

#include <hotplace/sdk/net/basic/trial/secure_client_socket.hpp>
#include <memory>

namespace hotplace {
namespace net {

/**
 * @brief   TLS client socket
 * @sample
 *          trial_tls_client_socket cli;
 *          ret = cli.connect(addr, port, tmo);
 *          if (errorcode_t::success == ret) {
 *              ret = cli.send(msg.c_str(), msg.size(), &cbsent);
 *              if (errorcode_t::success == ret) {
 *                  cli.read(buf, bufsize, &cbread);
 *              }
 *          }
 */
class HOTPLACE_NET_API trial_tls_client_socket : public secure_client_socket {
   public:
    trial_tls_client_socket(tls_version_t spec = tls1_3);
    // Start a new TLS connection with only the source session's resumption-ticket cache.
    trial_tls_client_socket(const tls_session& resumption_source, tls_version_t spec = tls1_3);
    virtual ~trial_tls_client_socket();

    virtual return_t send(const char* ptr_data, size_t size_data, size_t* cbsent);
    virtual return_t close() override;

    virtual int socket_type() const;

    virtual uint32 get_scheme() const;

   protected:
    virtual return_t do_send(binary_t& bin);

   private:
    return_t retire_transport();

    critical_section _send_lock;
    std::shared_ptr<tls1_2_resumption_ticket_store> _tls12_ticket_store;
};

}  // namespace net
}  // namespace hotplace

#endif
