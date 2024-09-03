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
    BIO* _sbio_read;
    BIO* _sbio_write;

    _tls_context_t() : _signature(0), _flags(0), _socket(-1), _ssl(nullptr), _sbio_read(nullptr), _sbio_write(nullptr) {}
} tls_context_t;

transport_layer_security::transport_layer_security(SSL_CTX* x509) : _x509(x509) {
    if (nullptr == x509) {
        throw errorcode_t::insufficient;
    }
    SSL_CTX_up_ref(x509);
    _shared.make_share(this);
}

transport_layer_security::~transport_layer_security() { SSL_CTX_free(_x509); }

int transport_layer_security::addref() { return _shared.addref(); }

int transport_layer_security::release() { return _shared.delref(); }

return_t transport_layer_security::connect(tls_context_t** handle, int type, const char* address, uint16 port, uint32 timeout_connect) {
    return_t ret = errorcode_t::success;
    socket_t sock = INVALID_SOCKET;
    tls_context_t* context = nullptr;
    sockaddr_storage_t sockaddr_address = {
        0,
    };

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = create_socket(&sock, &sockaddr_address, type, address, port);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = connect_socket_addr(sock, &sockaddr_address, sizeof(sockaddr_address), timeout_connect);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = connect(&context, sock, timeout_connect);
        if (errorcode_t::success == ret) {
            context->_flags = tls_context_flag_t::closesocket_ondestroy;
        } else {
            __leave2;
        }

        *handle = context;
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            close_socket(sock, true, 0);
        }
    }
    return ret;
}

return_t transport_layer_security::connect(tls_context_t** handle, socket_t sock, uint32 timeout_seconds) {
    return_t ret = errorcode_t::success;
    BIO* sbio_read = nullptr;
    BIO* sbio_write = nullptr;
    SSL* ssl = nullptr;
    tls_context_t* context = nullptr;

    __try2 {
        if (nullptr == handle || INVALID_SOCKET == sock) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (nullptr == _x509) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }
        SSL_CTX* tls_ctx = _x509;

        __try_new_catch(context, new tls_context_t, ret, __leave2);

        ssl = SSL_new(tls_ctx);
        if (nullptr == ssl) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        SSL_set_fd(ssl, (int)sock);

        ret = tls_connect(sock, ssl, timeout_seconds, 1);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        sbio_read = BIO_new(BIO_s_mem());
        sbio_write = BIO_new(BIO_s_mem());
        SSL_set_bio(ssl, sbio_read, sbio_write);

        context->_socket = sock;
        context->_ssl = ssl;

        context->_sbio_read = sbio_read;
        context->_sbio_write = sbio_write;
        context->_signature = TLS_CONTEXT_SIGNATURE;

        *handle = context;
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            if (nullptr != ssl) {
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

        if (nullptr == _x509) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }
        SSL_CTX* tls_ctx = _x509;

        __try_new_catch(context, new tls_context_t, ret, __leave2);

        /* SSL_accept */
        ssl = SSL_new(tls_ctx);
        SSL_set_fd(ssl, (int)fd);

        set_sock_nbio(fd, 1);

        fd_set rfdset;
        fd_set wfdset;

        int status = -1;
        do {
            FD_ZERO(&rfdset);
            FD_ZERO(&wfdset);

            status = SSL_accept(ssl);
            int condition = SSL_get_error(ssl, status);
            switch (condition) {
                case SSL_ERROR_NONE:
                    status = 0;
                    break;
                case SSL_ERROR_WANT_WRITE:
                    FD_SET(fd, &wfdset);
                    status = 1;
                    break;
                case SSL_ERROR_WANT_READ:
                    FD_SET(fd, &rfdset);
                    status = 1;
                    break;
                case SSL_ERROR_ZERO_RETURN:
                case SSL_ERROR_SYSCALL:
                    // peer closed connection during SSL handshake
                    status = -1;
                    break;
                default:
                    status = -1;
                    break;
            }
            if (1 == status) {
                struct timeval tv;
                tv.tv_sec = 2;
                tv.tv_usec = 0;

                status = select(fd + 1, &rfdset, &wfdset, nullptr, &tv);
                // 0 timeout
                // -1 error
                if (status >= 1) {
                    status = 1;
                } else {
                    status = -1;
                }
            }
        } while ((1 == status) && !SSL_is_init_finished(ssl));

        set_sock_nbio(fd, 0);

        if (status < 0) {
            ret = get_lasterror(status);
            __leave2;
        }

        /* SSL_set_bio */
        sbio_read = BIO_new(BIO_s_mem());
        sbio_write = BIO_new(BIO_s_mem());
        SSL_set_bio(ssl, sbio_read, sbio_write);

        /* compose the context */
        context->_socket = fd;
        context->_ssl = ssl;

        context->_sbio_read = sbio_read;
        context->_sbio_write = sbio_write;
        context->_signature = TLS_CONTEXT_SIGNATURE;

        *handle = context;
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            if (INVALID_SOCKET != fd) {
#if defined __linux__
                ::close(fd);
#elif defined _WIN32 || defined _WIN64
                closesocket(fd);
#endif
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

return_t transport_layer_security::dtls_listen(tls_context_t** handle, socket_t fd, struct sockaddr* addr, socklen_t addrlen) {
    return_t ret = errorcode_t::success;

    BIO* sbio_read = nullptr;
    BIO* sbio_write = nullptr;
    SSL* ssl = nullptr;
    tls_context_t* context = nullptr;
    BIO_ADDR* bio_addr = nullptr;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (nullptr == _x509) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }
        SSL_CTX* tls_ctx = _x509;

        __try_new_catch(context, new tls_context_t, ret, __leave2);

        /* SSL_accept */
        ssl = SSL_new(tls_ctx);
        SSL_set_fd(ssl, (int)fd);

        int status = -1;
        bio_addr = BIO_ADDR_new();
        status = DTLSv1_listen(ssl, bio_addr);
        if (status < 0) {
            ret = get_lasterror(status);
            __leave2;
        }
        BIO_ADDR_to_sockaddr(bio_addr, addr, addrlen);

        /* SSL_set_bio */
        sbio_read = BIO_new(BIO_s_mem());
        sbio_write = BIO_new(BIO_s_mem());
        SSL_set_bio(ssl, sbio_read, sbio_write);

        /* compose the context */
        context->_socket = fd;
        context->_ssl = ssl;

        context->_sbio_read = sbio_read;
        context->_sbio_write = sbio_write;
        context->_signature = TLS_CONTEXT_SIGNATURE;

        *handle = context;
    }
    __finally2 {
        if (bio_addr) {
            BIO_ADDR_free(bio_addr);
        }
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

        SSL_shutdown(handle->_ssl);
        SSL_free(handle->_ssl);

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
        if (tls_io_flag_t::read_bio_write & mode) {
            BIO_write(handle->_sbio_read, buffer, (int)size_read);
        }
        if (tls_io_flag_t::read_ssl_read & mode) {
            int written = BIO_number_written(handle->_sbio_read);
            ret_recv = SSL_read(handle->_ssl, buffer, (int)buffer_size);
            if (ret_recv <= 0) {
                int ssl_error = SSL_get_error(handle->_ssl, ret_recv);
                if (SSL_ERROR_WANT_READ == ssl_error) {
                    ret = errorcode_t::pending;
                } else {
                    ret = errorcode_t::internal_error;
                }
                __leave2;
            } else {
                if (buffer_size < (size_t)written) {
                    ret = errorcode_t::more_data;
                    if (nullptr != cbread) {
                        *cbread = buffer_size;
                    }
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
        if (tls_io_flag_t::read_bio_write & mode) {
            BIO_write(handle->_sbio_read, buffer, (int)size_read);
        }
        if (tls_io_flag_t::read_ssl_read & mode) {
            int written = BIO_number_written(handle->_sbio_read);
            ret_recv = SSL_read(handle->_ssl, buffer, (int)buffer_size);
            if (ret_recv <= 0) {
                int ssl_error = SSL_get_error(handle->_ssl, ret_recv);
                if (SSL_ERROR_WANT_READ == ssl_error) {
                    ret = errorcode_t::pending;
                } else {
                    ret = errorcode_t::internal_error;
                }
                __leave2;
            } else {
                if (buffer_size < (size_t)written) {
                    ret = errorcode_t::more_data;
                    if (nullptr != cbread) {
                        *cbread = buffer_size;
                    }
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

        if (tls_io_flag_t::send_ssl_write & mode) {
            int ret_write = SSL_write(handle->_ssl, data, (int)size_data);

            if (ret_write < 1) {
                ret = errorcode_t::internal_error;
                __leave2;
            }
            if (size_sent) {
                *size_sent = ret_write;
            }
        }

        int written = BIO_number_written(handle->_sbio_write);

        int ret_read = 0;
        std::vector<char> buf;
        buf.resize(written);

        if (tls_io_flag_t::send_bio_read & mode) {
            ret_read = BIO_read(handle->_sbio_write, &buf[0], buf.size());
            if (ret_read < 1) {
                ret = errorcode_t::internal_error;
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

        if (tls_io_flag_t::send_ssl_write & mode) {
            int ret_write = SSL_write(handle->_ssl, data, (int)size_data);

            if (ret_write < 1) {
                ret = errorcode_t::internal_error;
                __leave2;
            }
            if (size_sent) {
                *size_sent = ret_write;
            }
        }

        int written = BIO_number_written(handle->_sbio_write);

        int ret_read = 0;
        std::vector<char> buf;
        buf.resize(written);

        if (tls_io_flag_t::send_bio_read & mode) {
            ret_read = BIO_read(handle->_sbio_write, &buf[0], buf.size());
            if (ret_read < 1) {
                ret = errorcode_t::internal_error;
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

SSL_CTX* transport_layer_security::get() { return _x509; }

}  // namespace net
}  // namespace hotplace
