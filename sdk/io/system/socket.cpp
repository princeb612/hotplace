/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

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
        if (address_t::addr_host == address_type_adjusted) {
            hints.ai_flags = AI_PASSIVE;
        } else {
            hints.ai_flags = AI_NUMERICHOST;
        }

        char string_port[1 << 3];
        snprintf(string_port, RTL_NUMBER_OF(string_port), "%d", port);
        ret_function = getaddrinfo(address_pointer, string_port, &hints, &addrinf);
        if (0 != ret_function) {
            ret = get_lasterror(ret_function);
            __leave2;
        }

        addrinf_traverse = addrinf;
        do {
            if (AF_INET == addrinf_traverse->ai_family || AF_INET6 == addrinf_traverse->ai_family) {
                s = socket(addrinf_traverse->ai_family, addrinf_traverse->ai_socktype, addrinf_traverse->ai_protocol);
                if (INVALID_SOCKET != s) {
                    break;
                }
            }
            addrinf_traverse = addrinf_traverse->ai_next;
        } while (nullptr != addrinf_traverse);

        if (INVALID_SOCKET == s) {
            ret = get_lasterror(s);
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
            ret = get_lasterror(ret_function);
            __leave2;
        }

        addrinf_traverse = addrinf;

        while (nullptr != addrinf_traverse) {
            for (index = 0; index < size_vector; index++) {
                if ((int)vector_family[index] == addrinf_traverse->ai_family) {
                    socket_t sock = INVALID_SOCKET;
                    __try2 {
#if defined __linux__
                        sock = socket(addrinf_traverse->ai_family, addrinf_traverse->ai_socktype, addrinf_traverse->ai_protocol);
#elif defined _WIN32 || defined _WIN64
                        sock = WSASocket(addrinf_traverse->ai_family, addrinf_traverse->ai_socktype, addrinf_traverse->ai_protocol, nullptr, 0,
                                         WSA_FLAG_OVERLAPPED);
#endif
                        if (INVALID_SOCKET == sock) {
                            ret = get_lasterror(sock);
                            __leave2;
                        }

#if defined __linux__
                        if (PF_INET6 == addrinf_traverse->ai_family) {
                            int only_ipv6 = 1;
                            setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &only_ipv6, sizeof(only_ipv6));
                        }
#endif
                        int reuse = 1;
                        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char*)&reuse, sizeof(reuse));

                        ret_function = bind(sock, addrinf_traverse->ai_addr, (int)addrinf_traverse->ai_addrlen);
                        if (0 != ret_function) {
                            ret = get_lasterror(ret_function);
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
                                ret = get_lasterror(ret_function);
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
            ret = connect_socket_addr(sock, &addr, sizeof(addr), dwTimeout);
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

return_t connect_socket_addr(socket_t sock, sockaddr_storage_t* addr, size_t addrlen, uint32 wto) {
    return_t ret = errorcode_t::success;
    int ret_routine = 0;

    __try2 {
        if (nullptr == addr) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (0 == wto) {
            wto = NET_DEFAULT_TIMEOUT;
        }

        set_sock_nbio(sock, 1);

        ret_routine = connect(sock, reinterpret_cast<sockaddr*>(addr), (int)addrlen);
        if (-1 == ret_routine) {
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
                FD_SET(sock, &fds);                                               /* VC 6.0 - C4127 */
                ret_routine = select((int)sock + 1, nullptr, &fds, nullptr, &tv); /* zero if timeout, -1 if an error occurred */
                if (0 == ret_routine) {
                    ret = errorcode_t::timeout;
                } else if (ret_routine < 0) {
                    ret = get_lasterror(ret_routine);
                }
            }
        }

        set_sock_nbio(sock, 0);

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

return_t close_listener(unsigned int count, socket_t* sockets) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == sockets) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        for (unsigned int i = 0; i < count; i++) {
            if (INVALID_SOCKET != sockets[i]) {
                close_socket(sockets[i], true, 0);
                sockets[i] = INVALID_SOCKET;
            }
        }
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            // do nothing
        }
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
        ret = get_lasterror(ret_select);
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
        ret = get_lasterror(ret_fcntl);
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
            ret = get_lasterror(rc);
        } else if (0 == rc) {
            ret = errorcode_t::bad_format;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t typeof_socket(socket_t sock, int& type) {
    return_t ret = errorcode_t::success;
    socklen_t optlen = sizeof(type);
    int rc = getsockopt(sock, SOL_SOCKET, SO_TYPE, (char*)&type, &optlen);
    ret = get_lasterror(rc);
    return ret;
}

}  // namespace io
}  // namespace hotplace
