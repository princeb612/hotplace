/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base.hpp>
#include <sdk/net/server/network_session.hpp>

namespace hotplace {
namespace net {

network_session::network_session(tcp_server_socket* serversocket) {
    _shared.make_share(this);
    _session.svr_socket = serversocket;
}

network_session::~network_session() {
    get_server_socket()->close((socket_t)_session.netsock.cli_socket, _session.tls_handle);
    // do nothing
}

return_t network_session::connected(handle_t client_socket, sockaddr_storage_t* sockaddr, tls_context_t* tls_handle) {
    return_t ret = errorcode_t::success;

    _session.netsock.cli_socket = client_socket;
    memcpy(&(_session.netsock.cli_addr), sockaddr, sizeof(sockaddr_storage_t));
    _session.tls_handle = tls_handle;
    return ret;
}

return_t network_session::ready_to_read() {
    return_t ret = errorcode_t::success;

#if defined _WIN32 || defined _WIN64
    /* asynchronous read */
    DWORD dwFlags = 0;
    DWORD dwRecvBytes = 0;

    WSARecv((socket_t)_session.netsock.cli_socket, &(_session.wsabuf_pair.r.wsabuf), 1, &dwRecvBytes, &dwFlags, &(_session.wsabuf_pair.r.overlapped), nullptr);
#endif
    return ret;
}

return_t network_session::send(const char* data_ptr, size_t size_data) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == data_ptr) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        size_t cbsent = 0;
        ret = get_server_socket()->send((socket_t)_session.netsock.cli_socket, _session.tls_handle, data_ptr, size_data, &cbsent);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t network_session::send(const byte_t* data_ptr, size_t size_data) { return send((char*)data_ptr, size_data); }

net_session_socket_t* network_session::socket_info() { return &_session.netsock; }

#if defined _WIN32 || defined _WIN64
WSABUF* network_session::wsabuf_read() { return &_session.wsabuf_pair.r.wsabuf; }
#endif

network_stream* network_session::getstream() { return &_stream; }

network_stream* network_session::getrequest() { return &_request; }

int network_session::get_priority() { return _session.priority; }

void network_session::set_priority(int priority) { _session.priority = priority; }

int network_session::addref() { return _shared.addref(); }

int network_session::release() { return _shared.delref(); }

return_t network_session::produce(t_mlfq<network_session>* q, byte_t* buf_read, size_t size_buf_read) {
    return_t ret = errorcode_t::success;
    critical_section_guard guard(_lock);

    __try2 {
        if (nullptr == q) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

#if defined _WIN32 || defined _WIN64
        // buf_read, size_buf_read transmitted
#elif defined __linux__
        // read
        size_buf_read = RTL_NUMBER_OF(_session.buffer);
        buf_read = (byte_t*)_session.buffer;
#endif

        return_t result = errorcode_t::success;

        if (_session.tls_handle) { /* TLS */
            size_t cbread = 0;
            bool data_ready = false;
            int mode = 0;
#if defined __linux__
            mode = tls_io_flag_t::read_epoll;
#elif defined _WIN32 || defined _WIN64
            mode = tls_io_flag_t::read_iocp;
#endif
            ret = get_server_socket()->read((socket_t)_session.netsock.cli_socket, _session.tls_handle, mode, (char*)buf_read, size_buf_read, nullptr);
            if (errorcode_t::success != ret) {
                __leave2;
            }

            while (true) {
                result = get_server_socket()->read((socket_t)_session.netsock.cli_socket, _session.tls_handle, tls_io_flag_t::read_ssl_read, (char*)buf_read,
                                                   size_buf_read, &cbread); /*SSL_read */
                if (errorcode_t::success == result || errorcode_t::more_data == result) {
                    getstream()->produce(buf_read, cbread);

                    data_ready = true;
                } else {
                    break;
                }
            }

            if (data_ready) {
                q->push(get_priority(), this);
            }
        } else { /* wo TLS */
#if defined __linux__
            size_t cbread = 0;
            ret = get_server_socket()->read((socket_t)_session.netsock.cli_socket, _session.tls_handle, 0, (char*)buf_read, size_buf_read, &cbread);
            if (errorcode_t::success == ret) {
                getstream()->produce(buf_read, cbread);
                q->push(get_priority(), this);
            }
#elif defined _WIN32 || defined _WIN64
            getstream()->produce(buf_read, size_buf_read);
            q->push(get_priority(), this);
#endif
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t network_session::consume(network_protocol_group* protocol_group, network_stream_data** ptr_network_stream_buffer) {
    return_t ret = errorcode_t::success;

    _request.read(protocol_group, &_stream);
    ret = _request.consume(ptr_network_stream_buffer);
    return ret;
}

tcp_server_socket* network_session::get_server_socket() { return _session.svr_socket; }

network_session_data* network_session::get_session_data() { return &_session_data; }

http2_session& network_session::get_http2_session() { return _http2_session; }

network_session_manager::network_session_manager() {
    // do nothing
}

network_session_manager::~network_session_manager() {
    // do nothing
}

return_t network_session_manager::connected(handle_t client_socket, sockaddr_storage_t* sockaddr, tcp_server_socket* svr_socket, tls_context_t* tls_handle,
                                            network_session** ptr_session_object) {
    return_t ret = errorcode_t::success;
    network_session_map_pib_t pairib;
    network_session* session_object = nullptr;

    __try2 {
        critical_section_guard guard(_session_lock);

        pairib = _session_map.insert(std::make_pair(client_socket, (network_session*)nullptr));
        if (true == pairib.second) {
            session_object = new network_session(svr_socket);
            pairib.first->second = session_object;
            session_object->connected(client_socket, sockaddr, tls_handle);
            *ptr_session_object = session_object;
        } else {
            ret = errorcode_t::already_assigned;
        }
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t network_session_manager::find(handle_t client_socket, network_session** ptr_session_object) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == ptr_session_object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        critical_section_guard guard(_session_lock);
        network_session_map_t::iterator iter = _session_map.find(client_socket);
        if (_session_map.end() == iter) {
            ret = errorcode_t::not_found;
        } else {
            network_session* session_object = iter->second;
            session_object->addref(); /* in-use */
            *ptr_session_object = session_object;
        }
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

network_session* network_session_manager::operator[](handle_t client_socket) {
    network_session* ptr_session_object = nullptr;

    find(client_socket, &ptr_session_object);
    return ptr_session_object;
}

return_t network_session_manager::ready_to_close(handle_t client_socket, network_session** ptr_session_object) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == ptr_session_object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        critical_section_guard guard(_session_lock);
        network_session_map_t::iterator iter = _session_map.find(client_socket);
        if (_session_map.end() == iter) {
            ret = errorcode_t::not_found;
        } else {
            network_session* session_object = iter->second;
            *ptr_session_object = session_object;

            _session_map.erase(iter);
        }
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

}  // namespace net
}  // namespace hotplace
