/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/net/socket/sdk.hpp>

namespace hotplace {
namespace net {

return_t create_socket (socket_t* socket_created, sockaddr_storage_t* sockaddr_created, int address_type, const char* address, uint16 port)
{
    return_t ret = errorcode_t::success;
    socket_t s = INVALID_SOCKET;
    ADDRESS_TYPE address_type_adjusted = ADDRESS_TYPE_IPV4;
    int ret_function = 0;
    char* address_pointer = nullptr;
    addrinfo *addrinf = nullptr;
    addrinfo *addrinf_traverse = nullptr;

    __try2
    {
        if (nullptr == socket_created || nullptr == sockaddr_created || nullptr == address) {
            ret = errorcode_t::invalid_parameter;
            __leave2_trace (ret);
        }

        *socket_created = INVALID_SOCKET;

        //if (port <= 0 || port > 65535)
        //{
        //  ret = errorcode_t::invalid_parameter;
        //  __leave2_trace(ret);
        //}

        /*
         * IPv4 32bit   127.0.0.1
         * IPv6 128bit  ::1
         */
        if (nullptr != strstr (address, ":")) {
            address_type_adjusted = ADDRESS_TYPE_IPV6;
        } else {
            int ret_isdigit = 0;
            char tchTemp = 0;
            const char* tszTemp = address;
            while (true) {
                tchTemp = *tszTemp++;
                if (0 == tchTemp) {
                    break;
                }

                ret_isdigit = _istdigit (tchTemp);
                if (0 == ret_isdigit && '.' != tchTemp) {
                    address_type_adjusted = ADDRESS_TYPE_HOST;
                    break;
                }
            }
        }

        /*
           GetAddrInfoW 의 OS 지원 범위
           minimum supported : Windows Server 2003, Windows Vista, Windows XP with SP2

           ADDRINFOW  hints, *res = nullptr;
           ret_routine = GetAddrInfoW(tszAddress, szPort, &hints, &res);
         */

        struct addrinfo hints;

        address_pointer = const_cast<char*>(address);
        memset (&hints, 0, sizeof (hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = address_type;

        char string_port[1 << 7];
        snprintf (string_port, RTL_NUMBER_OF (string_port), "%d", port);

        if (ADDRESS_TYPE_HOST == address_type_adjusted) {
            hints.ai_flags = AI_PASSIVE;
        } else {
            hints.ai_flags = AI_NUMERICHOST;
        }

        ret_function = getaddrinfo (address_pointer, string_port, &hints, &addrinf);
        if (0 != ret_function) {
#if defined __linux__ || defined __APPLE__
            ret = GetEAIError (ret_function);
#elif defined _WIN32 || defined _WIN64
            ret = GetLastError ();
#endif
            __leave2_trace (ret);
        }

        addrinf_traverse = addrinf;
        do {
            if (AF_INET == addrinf_traverse->ai_family || AF_INET6 == addrinf_traverse->ai_family) {
                s = socket (addrinf_traverse->ai_family, addrinf_traverse->ai_socktype, addrinf_traverse->ai_protocol);
                if (INVALID_SOCKET != s) {
                    break;
                }
            }
            addrinf_traverse = addrinf_traverse->ai_next;
        } while (nullptr != addrinf_traverse);

        if (INVALID_SOCKET == s) {
            ret = GetLastError ();
            __leave2_trace (ret);
        }

#ifdef __STDC_WANT_SECURE_LIB__
        memcpy_s (sockaddr_created, sizeof (sockaddr_storage_t), addrinf_traverse->ai_addr, addrinf_traverse->ai_addrlen);
#else
        memcpy (sockaddr_created, addrinf_traverse->ai_addr, addrinf_traverse->ai_addrlen);
#endif

#if 0               // ip address
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
    __finally2
    {
        if ( nullptr != addrinf) {
            freeaddrinfo (addrinf);
            addrinf_traverse = nullptr;
        }

        if (errorcode_t::success != ret) {
            if (INVALID_SOCKET != s) {
#if defined __linux__ || defined __APPLE__
                close (s);
#elif defined _WIN32 || defined _WIN64
                closesocket (s);
#endif
            }

            // do nothing
        }
    }

    return ret;
}

return_t create_listener (unsigned int size_vector, unsigned int* vector_family, socket_t* vector_socket,
                          int protocol_type, uint32 port, bool support_win32_acceptex)
{
    return_t ret = errorcode_t::success;
    int socket_type = 0;
    int ipprotocol = 0;
    int ret_function = 0;
    uint16 index = 0;
    struct addrinfo hints;
    struct addrinfo *addrinf = nullptr;
    struct addrinfo *addrinf_traverse = nullptr;

    __try2
    {
        if (nullptr == vector_family) {
            ret = errorcode_t::invalid_parameter;
            __leave2_trace (ret);
        }
        if (nullptr == vector_socket) {
            ret = errorcode_t::invalid_parameter;
            __leave2_trace (ret);
        }

        for (index = 0; index < size_vector; index++) {
            vector_socket[index] = INVALID_SOCKET;
        }

        if (PROTOCOL_TCP == protocol_type) {
            socket_type = SOCK_STREAM;
            ipprotocol = IPPROTO_TCP;
        } else {
            socket_type = SOCK_DGRAM;
            ipprotocol = IPPROTO_UDP;
        }

        memset (&hints, 0, sizeof (hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = socket_type;
        hints.ai_protocol = ipprotocol;
        hints.ai_flags = AI_PASSIVE;

        char szPort[10];
        snprintf (szPort, 10, ("%d"), port);
        ret_function = getaddrinfo (nullptr, szPort, &hints, &addrinf);
        if (0 != ret_function) {
#if defined __linux__ || defined __APPLE__
            ret = GetEAIError (ret_function);
#elif defined _WIN32 || defined _WIN64
            ret = GetLastError ();
#endif
            __leave2_trace (ret);
        }

        addrinf_traverse = addrinf;

        while (nullptr != addrinf_traverse) {
            for (index = 0; index < size_vector; index++) {
                if ((int) vector_family[index] == addrinf_traverse->ai_family) {
                    socket_t sock = INVALID_SOCKET;
                    __try2
                    {
#if defined __linux__ || defined __APPLE__
                        sock = socket (addrinf_traverse->ai_family, addrinf_traverse->ai_socktype, addrinf_traverse->ai_protocol);
#elif defined _WIN32 || defined _WIN64
                        sock = WSASocket (addrinf_traverse->ai_family, addrinf_traverse->ai_socktype, addrinf_traverse->ai_protocol,
                                          nullptr, 0, WSA_FLAG_OVERLAPPED);
#endif
                        if (INVALID_SOCKET == sock) {
                            ret = GetLastError ();
                            __leave2_trace (ret);
                        }
#if defined __linux__ || defined __APPLE__
                        if (PF_INET6 == addrinf_traverse->ai_family) {
                            int only_ipv6 = 1;
                            setsockopt (sock, IPPROTO_IPV6, IPV6_V6ONLY, &only_ipv6, sizeof (only_ipv6));
                        }
#endif
                        int reuse = 1;
                        setsockopt (sock, SOL_SOCKET, SO_REUSEADDR, (char *) &reuse, sizeof (reuse));

                        ret_function = bind (sock, addrinf_traverse->ai_addr, (int) addrinf_traverse->ai_addrlen);
                        if (0 != ret_function) {
                            ret = GetLastError ();
                            __leave2_trace (ret);
                        }

                        if (PROTOCOL_TCP == protocol_type) {
#if defined _WIN32 || defined _WIN64
                            if (true == support_win32_acceptex) {
                                BOOL on = TRUE;
                                setsockopt (sock, SOL_SOCKET, SO_CONDITIONAL_ACCEPT, reinterpret_cast<char *>(&on), sizeof (on));
                            }
#endif

                            ret_function = listen (sock, SOMAXCONN);
                            if (SOCKET_ERROR == ret_function) {
                                ret = GetLastError ();
                                __leave2_trace (ret);
                            }
                        }

                        *(vector_socket + index) = sock;
                    }
                    __finally2
                    {
                        if (errorcode_t::success != ret) {
#if defined _WIN32 || defined _WIN64
                            closesocket (sock);
#else
                            close (sock);
#endif
                        }
                    }
                }
            }

            addrinf_traverse = addrinf_traverse->ai_next;
        }
    }
    __finally2
    {
        if (nullptr != addrinf) {
            freeaddrinfo (addrinf);
        }
        if (errorcode_t::success != ret) {
            if (nullptr != vector_socket) {
                for (index = 0; index < size_vector; index++) {
                    if (INVALID_SOCKET != vector_socket[index]) {
#if defined __linux__ || defined __APPLE__
                        close (vector_socket[index]);
#elif defined _WIN32 || defined _WIN64
                        closesocket (vector_socket[index]);
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

return_t connect_socket (socket_t* socket, int nType, const char* tszAddress, uint16 wPort, uint32 dwTimeout)
{
    UNREFERENCED_PARAMETER (nType);

    socket_t sock = INVALID_SOCKET;
    sockaddr_storage_t Addr;
    return_t ret = errorcode_t::success;

    __try2
    {
        ret = create_socket (&sock, &Addr, SOCK_STREAM, tszAddress, wPort);
        if (errorcode_t::success == ret) {
            ret = connect_socket_addr (sock, &Addr, sizeof (Addr), dwTimeout);
        }
        if (errorcode_t::success != ret) {
            __leave2_trace (ret);
        }

        *socket = sock;
    }
    __finally2
    {
        if ( errorcode_t::success != ret) {
#if defined __linux__ || defined __APPLE__
            close (sock);
#elif defined _WIN32 || defined _WIN64
            closesocket (sock);
#endif
            sock = INVALID_SOCKET;
        }
    }

    return ret;
}

return_t connect_socket_addr (socket_t sock, sockaddr_storage_t* pSockAddr, size_t sizeSockAddr, uint32 dwTimeout)
{
    return_t ret = errorcode_t::success;
    int ret_routine = 0;

    __try2
    {
        if (nullptr == pSockAddr) {
            ret = errorcode_t::invalid_parameter;
            __leave2_trace (ret);
        }

        if (0 == dwTimeout) {
            dwTimeout = NET_DEFAULT_TIMEOUT;
        }

        set_sock_nbio (sock, 1);

        ret_routine = connect (sock, reinterpret_cast<sockaddr*>(pSockAddr), (int) sizeSockAddr);
        if (SOCKET_ERROR == ret_routine) {

#if defined __linux__ || defined __APPLE__
            if (EINPROGRESS == errno)
#elif defined _WIN32 || defined _WIN64
            DWORD dwWsaGle = GetLastError ();
            if (WSAEWOULDBLOCK == dwWsaGle)
#endif
            {
                fd_set fds;
                struct timeval tv = { (int32) dwTimeout, 0 };                       // linux { time_t, suseconds_t }, windows { long, long }
                FD_ZERO (&fds);
                FD_SET (sock, &fds);                                                /* VC 6.0 - C4127 */
                ret_routine = select ((int) sock + 1, nullptr, &fds, nullptr, &tv); /* zero if timeout, SOCKET_ERROR if an error occurred */
                if (0 == ret_routine) {
                    ret = ERROR_TIMEOUT;
                }
#if defined __linux__ || defined __APPLE__
                else if (SOCKET_ERROR == ret_routine)
#elif defined _WIN32 || defined _WIN64
                else if (0 > ret_routine)
#endif
                {
                    ret = GetLastError ();
                }
            }

        }

        set_sock_nbio (sock, 0);

#if 0
        INT optval = 0;
        setsockopt (s, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char *>(&optval), sizeof (optval));
#endif
    }
    __finally2
    {
        if (errorcode_t::success != ret) {
            // do nothing
        }
    }

    return ret;
}

return_t close_socket (socket_t sock, bool bOnOff, uint16 wLinger)
{
    return_t ret = errorcode_t::success;

    if (INVALID_SOCKET != sock) {
        linger_t linger;
        linger.l_onoff = (true == bOnOff) ? 1 : 0;
        linger.l_linger = wLinger;
        setsockopt (sock, SOL_SOCKET, SO_LINGER, reinterpret_cast<char*>(&linger), sizeof (linger));

#if defined __linux__ || defined __APPLE__
        int nRet = close (sock);
#elif defined _WIN32 || defined _WIN64
        int nRet = closesocket (sock);
#endif
        if (0 != wLinger) {
            while (nRet < 0) {
#if defined __linux__ || defined __APPLE__
                if (EWOULDBLOCK == nRet) {
#elif defined _WIN32 || defined _WIN64
                if (WSAEWOULDBLOCK == nRet) {
#endif
                    fd_set fds;
                    timeval tv;

                    FD_ZERO (&fds);
                    FD_SET (sock, &fds); /* VC 6.0 - C4127 */

                    tv.tv_sec = 0;
                    tv.tv_usec = 100;

                    nRet = select ((int) sock + 1, &fds, nullptr, nullptr, &tv);
                    if (nRet > 0) {
#if defined __linux__ || defined __APPLE__
                        nRet = close (sock);
#elif defined _WIN32 || defined _WIN64
                        nRet = closesocket (sock);
#endif
                    }
                } else {
                    break;
                }
            }
        }
    }

    return ret;
}

return_t close_listener (unsigned int nSockets, socket_t* Sockets)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == Sockets) {
            ret = errorcode_t::invalid_parameter;
            __leave2_trace (ret);
        }

        for (uint16 i = 0; i < nSockets; i++) {
            if (INVALID_SOCKET != Sockets[i]) {
#if defined __linux__ || defined __APPLE__
                close (Sockets[i]);
#elif defined _WIN32 || defined _WIN64
                closesocket (Sockets[i]);
#endif
                Sockets[i] = INVALID_SOCKET;
            }
        }
    }
    __finally2
    {
        if (errorcode_t::success != ret) {
            // do nothing
        }
    }

    return ret;
}

return_t wait_socket (socket_t sock, uint32 dwMilliSeconds, uint32 dwFlag)
{
    return_t ret = errorcode_t::success;
    fd_set readset, writeset;

    FD_ZERO (&readset);
    FD_ZERO (&writeset);

    fd_set *preadset = nullptr;
    fd_set *pwriteset = nullptr;

    if (SOCK_WAIT_READABLE & dwFlag) {
        FD_SET (sock, &readset);
        preadset = &readset;
    }

    if (SOCK_WAIT_WRITABLE & dwFlag) {
        FD_SET (sock, &writeset);
        pwriteset = &writeset;
    }

    struct timeval tv;

    tv.tv_sec = dwMilliSeconds / 1000;
    tv.tv_usec = (dwMilliSeconds % 1000) * 1000;

    int ret_select = select ((int) sock + 1, preadset, pwriteset, nullptr, &tv);

    if (0 == ret_select) {
        ret = errorcode_t::timeout;
    } else if (0 > ret_select) {
        ret = GetLastError ();
    }

    return ret;
}

return_t set_sock_nbio (socket_t sock, uint32 nbio_mode)
{
    return_t ret = errorcode_t::success;
    int ret_fcntl = 0;

#if defined __linux__ || defined __APPLE__
    int flags = fcntl (sock, F_GETFL, 0);
    if (nbio_mode > 0) {
        if (0 == (O_NONBLOCK & flags)) {
            ret_fcntl = fcntl (sock, F_SETFL, flags | O_NONBLOCK);
        }
    } else {
        if (0 != (O_NONBLOCK & flags)) {
            ret_fcntl = fcntl (sock, F_SETFL, flags & ~O_NONBLOCK);
        }
    }
#elif defined _WIN32 || defined _WIN64
    ret_fcntl = ioctlsocket (sock, FIONBIO, &nbio_mode);
#endif
    if (SOCKET_ERROR == ret_fcntl) {
        ret = GetLastError ();
    }
    return ret;
}

}
}  // namespace
