/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/types.hpp>
#include <sdk/net/basic/server_socket.hpp>
#include <sdk/net/basic/tls/sdk.hpp>
#include <sdk/net/server/network_server.hpp>
#include <sdk/net/server/network_session.hpp>

namespace hotplace {
namespace net {

network_session_manager::network_session_manager() : _server_conf(nullptr) {
    // do nothing
}

network_session_manager::~network_session_manager() { shutdown(); }

void network_session_manager::set_server_conf(server_conf* conf) { _server_conf = conf; }

server_conf* network_session_manager::get_server_conf() { return _server_conf; }

return_t network_session_manager::connected(handle_t event_socket, sockaddr_storage_t* addr, server_socket* svr_socket, socket_context_t* socket_handle,
                                            network_session** ptr_session_object) {
    return_t ret = errorcode_t::success;
    network_session_map_pib_t pairib;
    network_session* session_object = nullptr;

    __try2 {
        if (nullptr == addr || nullptr == svr_socket || nullptr == ptr_session_object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        critical_section_guard guard(_session_lock);

        pairib = _session_map.insert(std::make_pair(event_socket, (network_session*)nullptr));
        if (true == pairib.second) {
            session_object = new network_session(svr_socket);
            server_conf* conf = get_server_conf();
            if (conf) {
                uint16 tcp_bufsize = conf->get(netserver_config_t::serverconf_tcp_bufsize);
                session_object->get_buffer()->set_bufsize(tcp_bufsize);  // 0 for default buffer size
            }
            pairib.first->second = session_object;
            session_object->connected(event_socket, addr, socket_handle);
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

return_t network_session_manager::find(handle_t event_socket, network_session** ptr_session_object) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == ptr_session_object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        critical_section_guard guard(_session_lock);
        network_session_map_t::iterator iter = _session_map.find(event_socket);
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

network_session* network_session_manager::operator[](handle_t event_socket) {
    network_session* ptr_session_object = nullptr;

    find(event_socket, &ptr_session_object);
    return ptr_session_object;
}

return_t network_session_manager::ready_to_close(handle_t event_socket, network_session** ptr_session_object) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == ptr_session_object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        critical_section_guard guard(_session_lock);
        network_session_map_t::iterator iter = _session_map.find(event_socket);
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

void network_session_manager::shutdown() {
    critical_section_guard guard(_session_lock);
    for (auto item : _session_map) {
        item.second->release();
    }
    _session_map.clear();
    for (auto item : _dgram_map) {
        item.second->release();
    }
    _dgram_map.clear();
}

return_t network_session_manager::get_dgram_session(network_session** ptr_session_object, handle_t listen_sock, server_socket* svr_socket,
                                                    socket_context_t* socket_handle) {
    return_t ret = errorcode_t::success;
    network_session_map_pib_t pairib;
    network_session* session_object = nullptr;

    __try2 {
        if (nullptr == svr_socket || nullptr == ptr_session_object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        critical_section_guard guard(_session_lock);

        pairib = _session_map.insert(std::make_pair(listen_sock, (network_session*)nullptr));
        if (true == pairib.second) {
            session_object = new network_session(svr_socket);
            server_conf* conf = get_server_conf();
            if (conf) {
                uint16 udp_bufsize = conf->get(netserver_config_t::serverconf_udp_bufsize);
                session_object->get_buffer()->set_bufsize(udp_bufsize);  // 0 for default buffer size
            }
            pairib.first->second = session_object;
            session_object->dtls_session_open(listen_sock);
            if (false == session_object->get_server_socket()->support_tls()) {
                session_object->udp_session_open(listen_sock);
            }
            *ptr_session_object = session_object;
        } else {
            session_object = pairib.first->second;
            *ptr_session_object = session_object;
        }

        if (session_object) {
            session_object->addref();
        }
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t network_session_manager::get_dgram_cookie_session(network_session** ptr_session_object, handle_t listen_sock, const sockaddr_storage_t* addr,
                                                           server_socket* svr_socket, socket_context_t* socket_handle) {
    return_t ret = errorcode_t::success;
    dgram_session_map_pib_t pairib;
    network_session* session_object = nullptr;

    __try2 {
        if (nullptr == addr || nullptr == svr_socket || nullptr == ptr_session_object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        critical_section_guard guard(_session_lock);

        binary_t cookie;
        generate_cookie_sockaddr(cookie, (sockaddr*)addr, sizeof(sockaddr_storage_t));

        pairib = _dgram_map.insert(std::make_pair(cookie, (network_session*)nullptr));
        if (true == pairib.second) {
            session_object = new network_session(svr_socket);
            server_conf* conf = get_server_conf();
            if (conf) {
                uint16 udp_bufsize = conf->get(netserver_config_t::serverconf_udp_bufsize);
                session_object->get_buffer()->set_bufsize(udp_bufsize);  // 0 for default buffer size
            }
            pairib.first->second = session_object;
            session_object->dtls_session_open(listen_sock);
            session_object->dtls_session_handshake();
            *ptr_session_object = session_object;
        } else {
            session_object = pairib.first->second;
            session_object->dtls_session_handshake();
            *ptr_session_object = session_object;
        }

        if (session_object) {
            session_object->addref();
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t network_session_manager::dgram_find(const sockaddr_storage_t* addr, network_session** ptr_session_object) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == addr || nullptr == ptr_session_object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        binary_t cookie;
        generate_cookie_sockaddr(cookie, (sockaddr*)addr, sizeof(sockaddr_storage_t));

        auto iter = _dgram_map.find(cookie);
        if (_dgram_map.end() == iter) {
            ret = errorcode_t::not_found;
            __leave2;
        } else {
            auto session_object = iter->second;
            session_object->addref();
            *ptr_session_object = session_object;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace net
}  // namespace hotplace
