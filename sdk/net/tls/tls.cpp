/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/crypto.hpp>
#include <sdk/io/system/socket.hpp>
#include <sdk/net/tls/sdk.hpp>
#include <sdk/net/tls/tls.hpp>

namespace hotplace {
using namespace crypto;
using namespace io;
namespace net {

#define TLS_CONTEXT_SIGNATURE 0x20120119

enum tls_context_flag_t {
    closesocket_ondestroy = (1 << 0),
};

typedef struct _tls_context_t {
    uint32 _signature;
    uint32 _flags;
    socket_t _socket;
    SSL* _ssl;

    _tls_context_t() : _signature(0), _flags(0), _socket(-1), _ssl(nullptr) {}
} tls_context_t;

transport_layer_security::transport_layer_security(SSL_CTX* ctx) : _ctx(ctx) {
    if (nullptr == ctx) {
        throw errorcode_t::insufficient;
    }
    SSL_CTX_up_ref(ctx);
    _shared.make_share(this);
}

transport_layer_security::transport_layer_security(x509cert* cert) : _ctx(nullptr) {
    if (cert) {
        _ctx = cert->get_ctx();
    }
    if (nullptr == _ctx) {
        throw errorcode_t::insufficient;
    }
    SSL_CTX_up_ref(_ctx);
    _shared.make_share(this);
}

transport_layer_security::~transport_layer_security() { SSL_CTX_free(_ctx); }

int transport_layer_security::addref() { return _shared.addref(); }

int transport_layer_security::release() { return _shared.delref(); }

return_t transport_layer_security::connect(tls_context_t** handle, int type, const char* address, uint16 port, uint32 wto) {
    return_t ret = errorcode_t::success;
    socket_t sock = INVALID_SOCKET;
    BIO* sbio_read = nullptr;
    BIO* sbio_write = nullptr;
    SSL* ssl = nullptr;
    tls_context_t* context = nullptr;
    sockaddr_storage_t addr = {
        0,
    };

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = create_socket(&sock, &addr, type, address, port);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = connect_socket_addr(sock, (sockaddr*)&addr, sizeof(addr), wto);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        __try_new_catch(context, new tls_context_t, ret, __leave2);

        ssl = SSL_new(_ctx);
        if (nullptr == ssl) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        SSL_set_fd(ssl, (int)sock);

        ret = do_connect(sock, ssl, wto, 1);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        context->_socket = sock;
        context->_ssl = ssl;

        sbio_read = BIO_new(BIO_s_mem());
        sbio_write = BIO_new(BIO_s_mem());
        SSL_set_bio(ssl, sbio_read, sbio_write);

        context->_signature = TLS_CONTEXT_SIGNATURE;
        context->_flags = tls_context_flag_t::closesocket_ondestroy;

        *handle = context;
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            if (ssl) {
                SSL_free(ssl);
            }
            if (context) {
                context->_signature = 0;
                delete context;
            }
            close_socket(sock, true, 0);
        }
    }
    return ret;
}

return_t transport_layer_security::connectto(tls_context_t** handle, socket_t sock, const char* address, uint16 port, uint32 wto) {
    return_t ret = errorcode_t::success;
    BIO* sbio_read = nullptr;
    BIO* sbio_write = nullptr;
    SSL* ssl = nullptr;
    tls_context_t* context = nullptr;
    sockaddr_storage_t addr = {
        0,
    };

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = addr_to_sockaddr(&addr, address, port);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = connectto(handle, sock, (sockaddr*)&addr, sizeof(addr), wto);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t transport_layer_security::connectto(tls_context_t** handle, socket_t sock, const sockaddr* addr, socklen_t addrlen, uint32 wto) {
    return_t ret = errorcode_t::success;
    BIO* sbio_read = nullptr;
    BIO* sbio_write = nullptr;
    SSL* ssl = nullptr;
    tls_context_t* context = nullptr;

    __try2 {
        if (nullptr == handle || nullptr == addr) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = connect_socket_addr(sock, addr, addrlen, wto);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        __try_new_catch(context, new tls_context_t, ret, __leave2);

        ssl = SSL_new(_ctx);
        if (nullptr == ssl) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        SSL_set_fd(ssl, (int)sock);

        ret = do_connect(sock, ssl, wto, 1);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        sbio_read = BIO_new(BIO_s_mem());
        sbio_write = BIO_new(BIO_s_mem());
        SSL_set_bio(ssl, sbio_read, sbio_write);

        context->_socket = sock;
        context->_ssl = ssl;

        context->_signature = TLS_CONTEXT_SIGNATURE;
        context->_flags = 0;

        *handle = context;
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            if (ssl) {
                SSL_free(ssl);
            }
            if (context) {
                context->_signature = 0;
                delete context;
            }
        }
    }
    return ret;
}

return_t transport_layer_security::accept(tls_context_t** handle, socket_t fd) {
    return_t ret = errorcode_t::success;

    BIO* sbio_read = nullptr;
    BIO* sbio_write = nullptr;
    SSL* ssl = nullptr;
    tls_context_t* context = nullptr;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (nullptr == _ctx) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        __try_new_catch(context, new tls_context_t, ret, __leave2);

        /* SSL_accept */
        ssl = SSL_new(_ctx);
        SSL_set_fd(ssl, (int)fd);

        /* compose the context */
        context->_signature = TLS_CONTEXT_SIGNATURE;
        context->_socket = fd;
        context->_ssl = ssl;

        set_sock_nbio(fd, 1);

        ret = do_accept(context);

        set_sock_nbio(fd, 0);

        if (errorcode_t::success != ret) {
            __leave2;
        }

        /* SSL_set_bio */
        sbio_read = BIO_new(BIO_s_mem());
        sbio_write = BIO_new(BIO_s_mem());
        SSL_set_bio(ssl, sbio_read, sbio_write);

        *handle = context;
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            if (INVALID_SOCKET != fd) {
                int socktype = 0;
                typeof_socket(fd, socktype);
                if (SOCK_STREAM == socktype) {
#if defined __linux__
                    ::close(fd);
#elif defined _WIN32 || defined _WIN64
                    closesocket(fd);
#endif
                }
            }
            if (nullptr != ssl) {
                // SSL_shutdown(ssl);
                SSL_free(ssl);
            }
            if (nullptr != context) {
                context->_signature = 0;
                delete context;
            }
        }
    }

    return ret;
}

return_t transport_layer_security::dtls_open(tls_context_t** handle, socket_t fd) {
    return_t ret = errorcode_t::success;

    BIO* sbio = nullptr;
    SSL* ssl = nullptr;
    tls_context_t* context = nullptr;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (nullptr == _ctx) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        __try_new_catch(context, new tls_context_t, ret, __leave2);

        /* SSL_accept */
        ssl = SSL_new(_ctx);
        SSL_set_fd(ssl, (int)fd);

        /* SSL_set_bio - BIO_s_mem for TCP, BIO_s_datagram for UDP */
        sbio = BIO_new_dgram(fd, BIO_NOCLOSE);
        SSL_set_bio(ssl, sbio, sbio);

        /* compose the context */
        context->_socket = fd;
        context->_ssl = ssl;

        context->_signature = TLS_CONTEXT_SIGNATURE;

        *handle = context;
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            if (nullptr != ssl) {
                // SSL_shutdown(ssl);
                SSL_free(ssl);
            }
            if (nullptr != context) {
                context->_signature = 0;
                delete context;
            }
        }
    }

    return ret;
}

return_t transport_layer_security::dtls_handshake(tls_context_t* handle, sockaddr* addr, socklen_t addrlen) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (TLS_CONTEXT_SIGNATURE != handle->_signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        auto fd = handle->_socket;
        auto ssl = handle->_ssl;

        if (1 == SSL_is_init_finished(ssl)) {
            __leave2;
        }

        int rc = 0;

        // SSL_get_state(ssl) -> TLS_ST_BEFORE

        do_dtls_listen(handle, addr, addrlen);

        // SSL_get_state(ssl) -> TLS_ST_SR_CLNT_HELLO

        do_accept(handle);

        // SSL_get_state(ssl) -> TLS_ST_OK
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t transport_layer_security::do_connect(socket_t fd, SSL* ssl, uint32 wto, uint32 nbio) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == ssl) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (0 == nbio) { /* blocking */
            int nRet = 0;
            nRet = SSL_connect(ssl);

            if (nRet <= 0) {
                ret = errorcode_t::internal_error;
                __leave2;
            }
        } else { /* non-blocking */
            set_sock_nbio(fd, 1);

            try {
                int rc = 1;
                int flags = 0;

                // TLS_ST_CW_CLNT_HELLO 0x0c
                // TLS_ST_CR_SRVR_HELLO 0x03
                // TLS_ST_CW_FINISHED   0x12
                // TLS_ST_OK            0x01

                do {
                    flags = 0;

                    rc = SSL_connect(ssl);

                    int condition = SSL_get_error(ssl, rc);
                    switch (condition) {
                        case SSL_ERROR_NONE:
                            rc = 0;
                            break;
                        case SSL_ERROR_WANT_WRITE:
                            flags |= SOCK_WAIT_WRITABLE;
                            rc = 1;
                            break;
                        case SSL_ERROR_WANT_READ:
                            flags |= SOCK_WAIT_READABLE;
                            rc = 1;
                            break;
                        case SSL_ERROR_ZERO_RETURN:
                        case SSL_ERROR_SYSCALL:
                            // peer closed connection during SSL handshake
                            rc = -1;
                            break;
                        default:
                            rc = -1;
                            break;
                    }
                    if (1 == rc) {
                        ret = wait_socket(fd, wto * 1000, flags);
                    }
                } while ((success == ret) && (1 != SSL_is_init_finished(ssl)));
            } catch (...) {
                /*
                 * openssl-1.0.1i SSL_connect crash
                 *    at X509_LOOKUP_by_subject
                 *      X509_LOOKUP *lu; // uninitialized
                 *      lu=sk_X509_LOOKUP_value(ctx->get_cert_methods,i); // if sk_X509_LOOKUP_value fails
                 *      j=X509_LOOKUP_by_subject(lu,type,name,&stmp); // crash
                 */
                ret = errorcode_t::internal_error;
            }

            set_sock_nbio(fd, 0);

            if (errorcode_t::success != ret) {
                __leave2;
            }
        }
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t transport_layer_security::do_dtls_listen(tls_context_t* handle, sockaddr* addr, socklen_t addrlen) {
    return_t ret = errorcode_t::success;
    BIO_ADDR* bio_addr = nullptr;
    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (TLS_CONTEXT_SIGNATURE != handle->_signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        auto ssl = handle->_ssl;
        int rc = 1;

        if (1 == SSL_is_init_finished(ssl)) {
            __leave2;
        }

        bio_addr = BIO_ADDR_new();

        do {
            rc = DTLSv1_listen(ssl, bio_addr);
            if (rc > 0) {
                if (addr) {
                    BIO_ADDR_to_sockaddr(bio_addr, addr, addrlen);
                    // basic_stream bs;
                    // dump_memory((byte_t*)addr, addrlen, &bs);
                    // printf("%s\n", bs.c_str());
                }
            } else {
                ret = get_opensslerror(rc);
            }
        } while (TLS_ST_SR_CLNT_HELLO != SSL_get_state(ssl));
    }
    __finally2 {
        if (bio_addr) {
            BIO_ADDR_free(bio_addr);
        }
    }
    return ret;
}

return_t transport_layer_security::do_accept(tls_context_t* handle) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (TLS_CONTEXT_SIGNATURE != handle->_signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        auto fd = handle->_socket;
        auto ssl = handle->_ssl;

        if (1 == SSL_is_init_finished(ssl)) {
            __leave2;
        }

        int rc = 1;
        int flags = 0;
        fd_set rfdset;
        fd_set wfdset;

        // TLS_ST_BEFORE        0x00
        // TLS_ST_SR_CLNT_HELLO 0x14
        // TLS_ST_OK            0x01

        do {
            flags = 0;

            rc = SSL_accept(ssl);
            int condition = SSL_get_error(ssl, rc);
            switch (condition) {
                case SSL_ERROR_NONE:
                    rc = 0;
                    break;
                case SSL_ERROR_WANT_WRITE:
                    flags |= SOCK_WAIT_WRITABLE;
                    rc = 1;
                    break;
                case SSL_ERROR_WANT_READ:
                    flags |= SOCK_WAIT_READABLE;
                    rc = 1;
                    break;
                case SSL_ERROR_ZERO_RETURN:
                case SSL_ERROR_SYSCALL:
                    // peer closed connection during SSL handshake
                    rc = -1;
                    break;
                default:
                    rc = -1;
                    break;
            }
            if (1 == rc) {
                ret = wait_socket(fd, 1 * 1000, flags);
            }
        } while ((success == ret) && (1 != SSL_is_init_finished(ssl)));

        if (rc < 1) {
            ret = get_opensslerror(rc);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t transport_layer_security::close(tls_context_t* handle) {
    return_t ret = errorcode_t::success;
    tls_context_t* context = nullptr;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (TLS_CONTEXT_SIGNATURE != handle->_signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        auto ssl = handle->_ssl;

        SSL_shutdown(ssl);
        SSL_free(ssl);

        if (tls_context_flag_t::closesocket_ondestroy == (handle->_flags & tls_context_flag_t::closesocket_ondestroy)) {
            close_socket(handle->_socket, true, 0);
        }

        handle->_signature = 0;
        delete handle;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t transport_layer_security::read(tls_context_t* handle, int mode, void* buffer, size_t buffer_size, size_t* cbread) {
    return_t ret = errorcode_t::success;

    int ret_recv = 0;

    __try2 {
        if (nullptr == handle || nullptr == buffer) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (TLS_CONTEXT_SIGNATURE != handle->_signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        if (nullptr != cbread) {
            *cbread = 0;
        }

        size_t size_read = buffer_size;
        if (tls_io_flag_t::read_socket_recv & mode) {
            ret_recv = ::recv(handle->_socket, (char*)buffer, buffer_size, 0);
            if (0 == ret_recv) { /* gracefully closed */
                ret = errorcode_t::disconnect;
                __leave2;
            }
            if (-1 == ret_recv) {
                ret = get_lasterror(ret_recv);
                __leave2;
            }

            size_read = ret_recv;
            if (nullptr != cbread) {
                *cbread = ret_recv;
            }
        }

        auto ssl = handle->_ssl;
        auto rbio = SSL_get_rbio(ssl);

        if (tls_io_flag_t::read_bio_write & mode) {
            BIO_write(rbio, buffer, (int)size_read);
        }

        if (tls_io_flag_t::read_ssl_read & mode) {
            int written = BIO_number_written(rbio);
            // SSL_read
            // ~ TLS 1.2 SSL_do_handshake(ssl)
            // TLS 1.3~ no handshake
            ret_recv = SSL_read(ssl, buffer, (int)buffer_size);
            if (ret_recv <= 0) {
                int ssl_error = SSL_get_error(ssl, ret_recv);
                if (SSL_ERROR_WANT_READ == ssl_error || SSL_ERROR_WANT_WRITE == ssl_error) {
                    ret = errorcode_t::pending;
                } else {
                    ret = errorcode_t::internal_error;
                }
                __leave2;
            } else {
                if (buffer_size < (size_t)written) {
                    ret = errorcode_t::more_data;
                }
                if (nullptr != cbread) {
                    *cbread = ret_recv;
                }
            }
        }
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t transport_layer_security::recvfrom(tls_context_t* handle, int mode, void* buffer, size_t buffer_size, size_t* cbread, struct sockaddr* addr,
                                            socklen_t* addrlen) {
    return_t ret = errorcode_t::success;
    int ret_recv = 0;

    __try2 {
        if (nullptr == handle || nullptr == buffer) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (TLS_CONTEXT_SIGNATURE != handle->_signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        if (nullptr != cbread) {
            *cbread = 0;
        }

        size_t size_read = buffer_size;
        if (tls_io_flag_t::read_socket_recv & mode) {
            ret_recv = ::recvfrom(handle->_socket, (char*)buffer, buffer_size, 0, addr, addrlen);
            if (0 == ret_recv) { /* gracefully closed */
                ret = errorcode_t::disconnect;
                __leave2;
            }
            if (-1 == ret_recv) {
                ret = get_lasterror(ret_recv);
                __leave2;
            }

            size_read = ret_recv;
            if (nullptr != cbread) {
                *cbread = ret_recv;
            }
        }

        auto ssl = handle->_ssl;
        auto rbio = SSL_get_rbio(ssl);

        if (tls_io_flag_t::read_bio_write & mode) {
            BIO_write(rbio, buffer, (int)size_read);
        }

        if (tls_io_flag_t::read_ssl_read & mode) {
            int written = BIO_number_written(rbio);
            ret_recv = SSL_read(ssl, buffer, (int)buffer_size);
            if (ret_recv <= 0) {
                int ssl_error = SSL_get_error(ssl, ret_recv);
                if (SSL_ERROR_WANT_READ == ssl_error || SSL_ERROR_WANT_WRITE == ssl_error) {
                    ret = errorcode_t::pending;
                } else {
                    ret = errorcode_t::internal_error;
                }
            } else {
                if (buffer_size < (size_t)written) {
                    ret = errorcode_t::more_data;
                }
                if (nullptr != cbread) {
                    *cbread = ret_recv;
                }
            }
        }
    }
    __finally2 {
        fflush(stdout);

        // do nothing
    }

    return ret;
}

return_t transport_layer_security::send(tls_context_t* handle, int mode, const char* data, size_t size_data, size_t* size_sent) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (size_sent) {
            *size_sent = 0;
        }

        if (TLS_CONTEXT_SIGNATURE != handle->_signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        auto ssl = handle->_ssl;
        auto wbio = SSL_get_wbio(ssl);

        if (tls_io_flag_t::send_ssl_write & mode) {
            int ret_write = SSL_write(ssl, data, (int)size_data);

            if (ret_write < 1) {
                ret = get_opensslerror(ret_write);
                __leave2;
            }
            if (size_sent) {
                *size_sent = ret_write;
            }
        }

        if (tls_io_flag_t::send_bio_read & mode) {
            int written = BIO_number_written(wbio);

            int ret_read = 0;
            std::vector<char> buf;
            buf.resize(written);

            ret_read = BIO_read(wbio, &buf[0], buf.size());
            if (ret_read < 1) {
                ret = get_opensslerror(ret_read);
                __leave2; /* too many traces here */
            }

            if (tls_io_flag_t::send_socket_send & mode) {
                ::send(handle->_socket, &buf[0], ret_read, 0);
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t transport_layer_security::sendto(tls_context_t* handle, int mode, const char* data, size_t size_data, size_t* size_sent, const struct sockaddr* addr,
                                          socklen_t addrlen) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (size_sent) {
            *size_sent = 0;
        }

        if (TLS_CONTEXT_SIGNATURE != handle->_signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        auto ssl = handle->_ssl;
        auto wbio = SSL_get_wbio(ssl);

        if (tls_io_flag_t::send_ssl_write & mode) {
            int ret_write = SSL_write(ssl, data, (int)size_data);

            if (ret_write < 1) {
                ret = get_opensslerror(ret_write);
                __leave2;
            }
            if (size_sent) {
                *size_sent = ret_write;
            }
        }

        if (tls_io_flag_t::send_bio_read & mode) {
            int written = BIO_number_written(wbio);

            int ret_read = 0;
            std::vector<char> buf;
            buf.resize(written);

            ret_read = BIO_read(wbio, &buf[0], buf.size());
            if (ret_read < 1) {
                ret = get_opensslerror(ret_read);
                __leave2; /* too many traces here */
            }

            if (tls_io_flag_t::send_socket_send & mode) {
                ::sendto(handle->_socket, &buf[0], ret_read, 0, addr, addrlen);
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

socket_t transport_layer_security::get_socket(tls_context_t* handle) {
    socket_t sock = INVALID_SOCKET;

    if (nullptr != handle) {
        sock = handle->_socket;
    }
    return sock;
}

SSL_CTX* transport_layer_security::get() { return _ctx; }

}  // namespace net
}  // namespace hotplace
