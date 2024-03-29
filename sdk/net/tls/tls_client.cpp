/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/basic/sdk.hpp>
#include <sdk/net/tls/tls_client.hpp>

namespace hotplace {
namespace net {

transport_layer_security_client::transport_layer_security_client(transport_layer_security* tls) : client_socket(), _tls(tls) {
    if (nullptr == tls) {
        throw errorcode_t::insufficiency;
    }
    tls->addref();
    _shared.make_share(this);
}

transport_layer_security_client::~transport_layer_security_client() { _tls->release(); }

int transport_layer_security_client::addref() { return _shared.addref(); }

int transport_layer_security_client::release() { return _shared.delref(); }

return_t transport_layer_security_client::connect(socket_t* sock, tls_context_t** tls_handle, const char* address, uint16 port, uint32 timeout) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == sock || nullptr == tls_handle || nullptr == address) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        tls_context_t* handle = nullptr;
        std::string addr = address;
        ret = _tls->connect(&handle, SOCK_STREAM, addr.c_str(), port, timeout);
        if (errorcode_t::success == ret) {
            *sock = _tls->get_socket(handle);
            *tls_handle = handle;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t transport_layer_security_client::close(socket_t sock, tls_context_t* tls_handle) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr != tls_handle) {
            _tls->close(tls_handle);
        }
        client_socket::close(sock, tls_handle);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t transport_layer_security_client::read(socket_t sock, tls_context_t* tls_handle, char* ptr_data, size_t size_data, size_t* cbread) {
    return_t ret = errorcode_t::success;

    /*
     * case ... server sent 10 bytes, and client recv buffer size 8
     * recv 8 (SSL_read SSL_ERROR_WANT_READ)
     * recv 2 (SSL_read SUCCESS)
     * in case read 8 bytes and 2 bytes remains, return errorcode_t::more_data
     */
    while (true) {
        ret = wait_socket(sock, get_ttl(), SOCK_WAIT_READABLE);
        if (errorcode_t::success == ret) {
            ret = _tls->read(tls_handle, tls_io_flag_t::read_ssl_read | tls_io_flag_t::read_bio_write | tls_io_flag_t::read_socket_recv, ptr_data, size_data,
                             cbread);
            if (errorcode_t::pending == ret) {
                continue;
            } else {
                break;
            }
        } else {
            break;
        }
    }
    return ret;
}

return_t transport_layer_security_client::more(socket_t sock, tls_context_t* tls_handle, char* ptr_data, size_t size_data, size_t* cbread) {
    return_t ret = errorcode_t::success;

    ret = _tls->read(tls_handle, tls_io_flag_t::read_ssl_read, ptr_data, size_data, cbread);
    return ret;
}

return_t transport_layer_security_client::send(socket_t sock, tls_context_t* tls_handle, const char* ptr_data, size_t size_data, size_t* cbsent) {
    return_t ret = errorcode_t::success;

    ret = _tls->send(tls_handle, tls_io_flag_t::send_all, ptr_data, size_data, cbsent);
    return ret;
}

}  // namespace net
}  // namespace hotplace
