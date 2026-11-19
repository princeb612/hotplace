/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   secure_prosumer.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_BASIC_TRIAL_SECUREPROSUMER__
#define __HOTPLACE_SDK_NET_BASIC_TRIAL_SECUREPROSUMER__

#include <hotplace/sdk/base/system/semaphore.hpp>
#include <hotplace/sdk/net/basic/trial/types.hpp>
#include <hotplace/sdk/net/tls/tls/types.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   TLS
 * @sa      trial_tls_client_socket, trial_tls_server_socket
 */
class HOTPLACE_NET_API secure_prosumer {
   public:
    secure_prosumer();

    /** Configure the maximum ciphertext bytes retained while the server awaits its 0-RTT decision. Defaults to 1 MiB; zero disables the configurable byte limit. A fixed
     * 64-record limit and its record-size-derived hard buffer ceiling always apply. */
    void set_pending_early_data_buffer_limit(uint64 limit);
    uint64 get_pending_early_data_buffer_limit() const;

    /** Mark the underlying transport as terminal and wake a pending consumer. */
    return_t notify_transport_closed();

    return_t produce(tls_session* session, tls_direction_t dir, std::function<void(basic_stream&, sockaddr_storage_t&)> func);
    return_t produce(tls_session* session, tls_direction_t dir, const byte_t* stream, size_t size, struct sockaddr* addr = nullptr, socklen_t* addrlen = nullptr);
    return_t consume(int sock_type, uint32 wto, char* ptr_data, size_t size_data, size_t* cbread, struct sockaddr* addr = nullptr, socklen_t* addrlen = nullptr);

   protected:
    friend class tls_handshake_encrypted_extensions;
    friend class tls_handshake_server_hello;
    return_t resume_pending_records(tls_session* session, tls_direction_t dir);
    return_t do_produce(tls_session* session, tls_direction_t dir, struct sockaddr* addr = nullptr, socklen_t* addrlen = nullptr);
    return_t do_produce(tls_session* session, tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, struct sockaddr* addr = nullptr,
                        socklen_t* addrlen = nullptr);

    critical_section _mlock;
    std::queue<socket_buffer_t> _mq;
    semaphore _msem;
    basic_stream _mbs;
    bool _producing;
    bool _resume_pending;
    bool _transport_closed;
    uint64 _pending_early_data_buffer_limit;
};

}  // namespace net
}  // namespace hotplace

#endif
