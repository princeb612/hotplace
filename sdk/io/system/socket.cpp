/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/basic/dump_memory.hpp>
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/string/string.hpp>
#include <sdk/base/unittest/trace.hpp>
#include <sdk/io/system/socket.hpp>

namespace hotplace {
namespace io {

enum address_t {
    addr_host = 0,  // aa.bb.cc
    addr_ipv4 = 1,  // 127.0.0.1
    addr_ipv6 = 2,  // fe80::f086:5f15:2045:5008%10
};

return_t create_socket(socket_t* socket_created, sockaddr_storage_t* sockaddr_created, int address_type, const char* address, uint16 port) {
    return_t ret = errorcode_t::success;
    socket_t s = INVALID_SOCKET;
    address_t address_type_adjusted = address_t::addr_ipv4;
    int ret_function = 0;
    char* address_pointer = nullptr;
    addrinfo* addrinf = nullptr;
    addrinfo* addrinf_traverse = nullptr;

    __try2 {
        if (nullptr == socket_created || nullptr == sockaddr_created || nullptr == address) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        *socket_created = INVALID_SOCKET;

        /**
         * IPv4 32bit   127.0.0.1
         * IPv6 128bit  ::1
         */
        if (nullptr != strstr(address, ":")) {
            address_type_adjusted = address_t::addr_ipv6;
        } else {
            int ret_isdigit = 0;
            char tchTemp = 0;
            const char* tszTemp = address;
            while (true) {
                tchTemp = *tszTemp++;
                if (0 == tchTemp) {
                    break;
                }

                ret_isdigit = isdigit(tchTemp);
                if (0 == ret_isdigit && '.' != tchTemp) {
                    address_type_adjusted = address_t::addr_host;
                    break;
                }
            }
        }

        /**
         * GetAddrInfoW
         * minimum supported : Windows Server 2003, Windows Vista, Windows XP with SP2
         *
         * ADDRINFOW  hints, *res = nullptr;
         * ret_routine = GetAddrInfoW(address, port_value, &hints, &res);
         */

        struct addrinfo hints;

        address_pointer = const_cast<char*>(address);
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = address_type;
        if (SOCK_STREAM == address_type) {
            hints.ai_protocol = IPPROTO_TCP;
        } else if (SOCK_DGRAM == address_type) {
            hints.ai_protocol = IPPROTO_UDP;
        }
        if (address_t::addr_host == address_type_adjusted) {
            hints.ai_flags = AI_PASSIVE;
        } else {
            hints.ai_flags = AI_NUMERICHOST;
        }

        char string_port[1 << 3];
        snprintf(string_port, RTL_NUMBER_OF(string_port), "%d", port);
        ret_function = getaddrinfo(address_pointer, string_port, &hints, &addrinf);
        if (0 != ret_function) {
            ret = get_lasterror(ret_function, wsaerror);
            __leave2;
        }

        sockaddr_storage_t sa = {0};

        addrinf_traverse = addrinf;
        do {
            auto family = addrinf_traverse->ai_family;
            auto socktype = addrinf_traverse->ai_socktype;
            auto protocol = addrinf_traverse->ai_protocol;

            if (AF_INET == family || AF_INET6 == family) {
#if defined __linux__
                s = socket(family, socktype, protocol);
#elif defined _WIN32 || defined _WIN64
                s = WSASocket(family, socktype, protocol, nullptr, 0, WSA_FLAG_OVERLAPPED);
#endif
                if (INVALID_SOCKET != s) {
#if defined _WIN32 || defined _WIN64
                    if (SOCK_DGRAM == socktype) {
                        // (IOCP) bind UDP socket
                        //        sin_addr = 0.0.0.0
                        //        sin.port = 0
                        sa.ss_family = family;
                        bind(s, (sockaddr*)&sa, sizeof(sa));
                    }
#endif

#if defined DEBUG
                    if (istraceable(trace_category_internal)) {
                        socket_advisor* advisor = socket_advisor::get_instance();
                        basic_stream dbs;
                        dbs.println("socket %d created family %i(%s) type %i(%s) protocol %i(%s)",  //
                                    s, family, advisor->nameof_family(family).c_str(),              //
                                    socktype, advisor->nameof_type(socktype).c_str(),               //
                                    protocol, advisor->nameof_protocol(protocol).c_str());          //
                        trace_debug_event(trace_category_internal, trace_event_socket, &dbs);
                    }
#endif

                    break;
                }
            }
            addrinf_traverse = addrinf_traverse->ai_next;
        } while (nullptr != addrinf_traverse);

        if (INVALID_SOCKET == s) {
            ret = get_lasterror(s, wsaerror);
            __leave2;
        }

#ifdef __STDC_WANT_SECURE_LIB__
        memcpy_s(sockaddr_created, sizeof(sockaddr_storage_t), addrinf_traverse->ai_addr, addrinf_traverse->ai_addrlen);
#else
        memcpy(sockaddr_created, addrinf_traverse->ai_addr, addrinf_traverse->ai_addrlen);
#endif

#if 0  // ip address
        char pAddress[BUFSIZE256];
        uint32 sizeAddress = BUFSIZE256;
        *(pAddress + 0) = 0;
        if (AF_INET == res->ai_family) {
            nRet = getnameinfo (reinterpret_cast<sockaddr_t*>(res->ai_addr), res->ai_addrlen, pAddress, sizeAddress, nullptr, 0, NI_NUMERICHOST);
        } else if (AF_INET6 == res->ai_family) {
            nRet = WSAAddressToString (reinterpret_cast<sockaddr_t*>(res->ai_addr), res->ai_addrlen, nullptr, pAddress, &sizeAddress);
        }
#endif

        *socket_created = s;
    }
    __finally2 {
        if (nullptr != addrinf) {
            freeaddrinfo(addrinf);
            addrinf_traverse = nullptr;
        }

        if (errorcode_t::success != ret) {
            if (INVALID_SOCKET != s) {
#if defined __linux__
                close(s);
#elif defined _WIN32 || defined _WIN64
                closesocket(s);
#endif
            }
        }
    }

    return ret;
}

return_t create_listener(unsigned int size_vector, unsigned int* vector_family, socket_t* vector_socket, int protocol_type, uint32 port,
                         bool support_win32_acceptex) {
    return_t ret = errorcode_t::success;
    int socket_type = 0;
    int ipprotocol = 0;
    int ret_function = 0;
    unsigned int index = 0;
    struct addrinfo hints;
    struct addrinfo* addrinf = nullptr;
    struct addrinfo* addrinf_traverse = nullptr;

    __try2 {
        if (nullptr == vector_family) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (nullptr == vector_socket) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        for (index = 0; index < size_vector; index++) {
            vector_socket[index] = INVALID_SOCKET;
        }

        if (IPPROTO_TCP == protocol_type) {
            socket_type = SOCK_STREAM;
            ipprotocol = IPPROTO_TCP;
        } else {
            socket_type = SOCK_DGRAM;
            ipprotocol = IPPROTO_UDP;
        }

        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = socket_type;
        hints.ai_protocol = ipprotocol;
        hints.ai_flags = AI_PASSIVE;

        char port_value[1 << 3];
        snprintf(port_value, sizeof(port_value), ("%d"), port);
        ret_function = getaddrinfo(nullptr, port_value, &hints, &addrinf);
        if (0 != ret_function) {
            ret = get_lasterror(ret_function, wsaerror);
            __leave2;
        }

        addrinf_traverse = addrinf;

        while (nullptr != addrinf_traverse) {
            auto family = addrinf_traverse->ai_family;
            auto socktype = addrinf_traverse->ai_socktype;
            auto protocol = addrinf_traverse->ai_protocol;

            for (index = 0; index < size_vector; index++) {
                if ((int)vector_family[index] == family) {
                    socket_t sock = INVALID_SOCKET;
                    __try2 {
#if defined __linux__
                        sock = socket(family, socktype, protocol);
#elif defined _WIN32 || defined _WIN64
                        sock = WSASocket(family, socktype, protocol, nullptr, 0, WSA_FLAG_OVERLAPPED);
#endif
                        if (INVALID_SOCKET == sock) {
                            ret = get_lasterror(sock, wsaerror);
                            __leave2;
                        }

#if defined DEBUG
                        if (istraceable(trace_category_internal)) {
                            socket_advisor* advisor = socket_advisor::get_instance();
                            basic_stream dbs;
                            dbs.println("socket %d created family %i(%s) type %i(%s) protocol %i(%s)",  //
                                        sock, family, advisor->nameof_family(family).c_str(),           //
                                        socktype, advisor->nameof_type(socktype).c_str(),               //
                                        protocol, advisor->nameof_protocol(protocol).c_str());          //
                            trace_debug_event(trace_category_internal, trace_event_socket, &dbs);
                        }
#endif

#if defined __linux__
                        if (PF_INET6 == family) {
                            int only_ipv6 = 1;
                            setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &only_ipv6, sizeof(only_ipv6));
                        }
#endif
                        int reuse = 1;
                        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char*)&reuse, sizeof(reuse));
#ifdef SO_REUSEPORT
                        // setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (char*)&reuse, sizeof(reuse));
#endif

                        ret_function = bind(sock, addrinf_traverse->ai_addr, (int)addrinf_traverse->ai_addrlen);
                        if (0 != ret_function) {
                            ret = get_lasterror(ret_function, wsaerror);
                            __leave2;
                        }

                        if (IPPROTO_TCP == protocol_type) {
#if defined _WIN32 || defined _WIN64
                            if (true == support_win32_acceptex) {
                                BOOL on = TRUE;
                                setsockopt(sock, SOL_SOCKET, SO_CONDITIONAL_ACCEPT, reinterpret_cast<char*>(&on), sizeof(on));
                            }
#endif

                            ret_function = listen(sock, SOMAXCONN);
                            if (-1 == ret_function) {
                                ret = get_lasterror(ret_function, wsaerror);
                                __leave2;
                            }
                        }

                        *(vector_socket + index) = sock;
                    }
                    __finally2 {
                        if (errorcode_t::success != ret) {
#if defined _WIN32 || defined _WIN64
                            closesocket(sock);
#else
                            close(sock);
#endif
                        }
                    }
                }
            }

            addrinf_traverse = addrinf_traverse->ai_next;
        }
    }
    __finally2 {
        if (nullptr != addrinf) {
            freeaddrinfo(addrinf);
        }
        if (errorcode_t::success != ret) {
            if (nullptr != vector_socket) {
                for (index = 0; index < size_vector; index++) {
                    if (INVALID_SOCKET != vector_socket[index]) {
#if defined __linux__
                        close(vector_socket[index]);
#elif defined _WIN32 || defined _WIN64
                        closesocket(vector_socket[index]);
#endif
                        vector_socket[index] = INVALID_SOCKET;
                    }
                }
            }

            // do nothing
        }
    }

    return ret;
}

return_t connect_socket(socket_t* socket, const char* address, uint16 port, uint32 dwTimeout) {
    socket_t sock = INVALID_SOCKET;
    sockaddr_storage_t addr;
    return_t ret = errorcode_t::success;

    __try2 {
        ret = create_socket(&sock, &addr, SOCK_STREAM, address, port);
        if (errorcode_t::success == ret) {
            ret = connect_socket_addr(sock, (sockaddr*)&addr, sizeof(addr), dwTimeout);
        }
        if (errorcode_t::success != ret) {
            __leave2;
        }

        *socket = sock;
    }
    __finally2 {
        if (errorcode_t::success != ret) {
#if defined __linux__
            close(sock);
#elif defined _WIN32 || defined _WIN64
            closesocket(sock);
#endif
            sock = INVALID_SOCKET;
        }
    }

    return ret;
}

return_t connect_socket_addr(socket_t sock, const sockaddr* addr, socklen_t addrlen, uint32 wto) {
    return_t ret = errorcode_t::success;
    int rc = 0;

    __try2 {
        if (nullptr == addr) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (0 == wto) {
            wto = NET_DEFAULT_TIMEOUT;
        }

        set_sock_nbio(sock, 1);

        rc = connect(sock, addr, addrlen);
        if (-1 == rc) {
#if defined __linux__
            if (EINPROGRESS == errno)
#elif defined _WIN32 || defined _WIN64
            DWORD dwWsaGle = GetLastError();
            if (WSAEWOULDBLOCK == dwWsaGle)
#endif
            {
                fd_set fds;
                struct timeval tv = {(int32)wto, 0};  // linux { time_t, suseconds_t }, windows { long, long }
                FD_ZERO(&fds);
                FD_SET(sock, &fds);                                      /* VC 6.0 - C4127 */
                rc = select((int)sock + 1, nullptr, &fds, nullptr, &tv); /* zero if timeout, -1 if an error occurred */
                if (0 == rc) {
                    ret = errorcode_t::error_connect;  // timeout
                } else if (rc < 0) {
                    ret = get_lasterror(rc, wsaerror);
                }
            }
        }

        set_sock_nbio(sock, 0);

#if defined __linux__
        // connect SO_ERROR 111 return 0
        int optval = 0;
        socklen_t optlen = sizeof(optval);
        rc = getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&optval, &optlen);
        if ((rc < 0) || (ECONNREFUSED == optval)) {
            ret = errorcode_t::disconnect;
        }

#if defined DEBUG
        if (istraceable(trace_category_internal)) {
            basic_stream dbs;
            dbs.println("connect SO_ERROR %i return %i", optval, rc);
            trace_debug_event(trace_category_internal, trace_event_socket, &dbs);
        }
#elif defined _WIN32 || defined _WIN64
        // connect SO_ERROR 0 return 0
#endif
#endif

#if 0
        INT optval = 0;
        setsockopt (s, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char *>(&optval), sizeof (optval));
#endif
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            // do nothing
        }
    }

    return ret;
}

return_t close_socket(socket_t sock, bool bOnOff, uint16 wLinger) {
    return_t ret = errorcode_t::success;

    if (INVALID_SOCKET != sock) {
        int how = 0;
#if defined __linux__
        how = SHUT_RDWR;
#elif defined _WIN32 || defined _WIN64
        how = SD_BOTH;
#endif
        shutdown(sock, how);

        int optval = 0;
        socklen_t optlen = sizeof(optval);
        getsockopt(sock, SOL_SOCKET, SO_TYPE, (char*)&optval, &optlen);

        if (SOCK_STREAM == optval) {
            linger_t linger;
            linger.l_onoff = (true == bOnOff) ? 1 : 0;
            linger.l_linger = wLinger;
            setsockopt(sock, SOL_SOCKET, SO_LINGER, reinterpret_cast<char*>(&linger), sizeof(linger));
        }

#if defined __linux__
        close(sock);
#elif defined _WIN32 || defined _WIN64
        closesocket(sock);
#endif
    }

    return ret;
}

return_t wait_socket(socket_t sock, uint32 milliSeconds, uint32 flags) {
    return_t ret = errorcode_t::success;
    fd_set readset, writeset;

    FD_ZERO(&readset);
    FD_ZERO(&writeset);

    fd_set* preadset = nullptr;
    fd_set* pwriteset = nullptr;

    if (SOCK_WAIT_READABLE & flags) {
        FD_SET(sock, &readset);
        preadset = &readset;
    }

    if (SOCK_WAIT_WRITABLE & flags) {
        FD_SET(sock, &writeset);
        pwriteset = &writeset;
    }

    struct timeval tv;

    tv.tv_sec = milliSeconds / 1000;
    tv.tv_usec = (milliSeconds % 1000) * 1000;

    int ret_select = select((int)sock + 1, preadset, pwriteset, nullptr, &tv);

    if (0 == ret_select) {
        ret = errorcode_t::timeout;
    } else if (0 > ret_select) {
        ret = get_lasterror(ret_select, wsaerror);
    }

    return ret;
}

return_t set_sock_nbio(socket_t sock, uint32 nbio_mode) {
    return_t ret = errorcode_t::success;
    int ret_fcntl = 0;

#if defined __linux__
    int flags = fcntl(sock, F_GETFL, 0);
    if (nbio_mode > 0) {
        if (0 == (O_NONBLOCK & flags)) {
            ret_fcntl = fcntl(sock, F_SETFL, flags | O_NONBLOCK);
        }
    } else {
        if (0 != (O_NONBLOCK & flags)) {
            ret_fcntl = fcntl(sock, F_SETFL, flags & ~O_NONBLOCK);
        }
    }
#elif defined _WIN32 || defined _WIN64
    ret_fcntl = ioctlsocket(sock, FIONBIO, &nbio_mode);
#endif
    if (-1 == ret_fcntl) {
        ret = get_lasterror(ret_fcntl, wsaerror);
    }
    return ret;
}

return_t addr_to_sockaddr(sockaddr_storage_t* storage, const char* address, uint16 port) {
    return_t ret = errorcode_t::success;
    __try2 {
        if ((nullptr == storage) || (nullptr == address)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        memset(storage, 0, sizeof(sockaddr_storage_t));

        int rc = 0;
        const char* temp = strstr(address, ":");
        if (temp) {
            struct sockaddr_in6* addr = (struct sockaddr_in6*)storage;
            addr->sin6_family = AF_INET6;
            addr->sin6_port = htons(port);
            rc = inet_pton(AF_INET6, address, &addr->sin6_addr);
        } else {
            struct sockaddr_in* addr = (struct sockaddr_in*)storage;
            addr->sin_family = AF_INET;
            addr->sin_port = htons(port);
            rc = inet_pton(AF_INET, address, &addr->sin_addr);
        }

        if (-1 == rc) {
            ret = get_lasterror(rc, wsaerror);
        } else if (0 == rc) {
            ret = errorcode_t::bad_format;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

void sockaddr_string(const sockaddr_storage_t& addr, std::string& address) {
    __try2 {
        address.clear();

        const char* ret = nullptr;
        char buf[INET6_ADDRSTRLEN] = {0};  // 45 + 1
        uint16 port = 0;

        auto family = addr.ss_family;
        if (AF_INET == family) {
            struct sockaddr_in* ipv4 = (struct sockaddr_in*)&addr;
            ret = inet_ntop(family, &ipv4->sin_addr, buf, sizeof(buf));
            port = ntohs(ipv4->sin_port);
        } else if (AF_INET6 == family) {
            struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)&addr;
            ret = inet_ntop(family, &ipv6->sin6_addr, buf, sizeof(buf));
            port = ntohs(ipv6->sin6_port);
        }
        if (ret) {
            address = format("%s:%i", buf, port);
        }
    }
    __finally2 {}
}

return_t typeof_socket(socket_t sock, int& type) {
    return_t ret = errorcode_t::success;
    socklen_t optlen = sizeof(type);
    int rc = getsockopt(sock, SOL_SOCKET, SO_TYPE, (char*)&type, &optlen);
    ret = get_lasterror(rc, wsaerror);
    return ret;
}

}  // namespace io
}  // namespace hotplace
