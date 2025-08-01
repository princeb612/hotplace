/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_IO_SYSTEM_SOCKET__
#define __HOTPLACE_SDK_IO_SYSTEM_SOCKET__

#include <sdk/base/system/critical_section.hpp>
#include <sdk/io/types.hpp>

namespace hotplace {
namespace io {

/**
 * @brief   create a socket, see alse close_socket to free
 * @param   socket_t*           socket_created [out] socket
 * @param   sockaddr_storage_t* sockaddr_created [out] socket address
 * @param   int                 address_type [in]
 * @param   const char*         address [in] 127.0.0.1 socket ipv4, ::1 socket ipv6
 * @param   uint16              port [in]
 * @return  error code (see error.hpp)
 * @example
 *          address = "127.0.0.1";
 *          port = 1234;
 *          socket_t sock = INVALID_SOCKET;
 *          sockaddr_storage_t sockaddr_address;
 *          create_socket (&sock, &sockaddr_address, SOCK_STREAM, address, port);
 *          // ...
 *          close_socket (sock, true, 0);
 */
return_t create_socket(socket_t* socket_created, sockaddr_storage_t* sockaddr_created, int address_type, const char* address, uint16 port);
/**
 * @brief   create a socket and listen, see alse CloseListener to free
 * @param   unsigned int size_vector    [in]
 * @param   unsigned int* vector_family [in] AF_INET, AF_INET6
 * @param   socket_t* vector_socket     [out]
 * @param   int protocol_type           [in] IPPROTO_TCP
 * @param   uint32 port                 [in]
 * @param   bool support_win32_acceptex [inopt]
 * @error   error code (see error.hpp)
 * @example
 *          unsigned int nFamily[2] = { AF_INET, AF_INET6 };  // IPv4 and IPv6
 *          socket_t sockets[2] = { INVALID_SOCKET, INVALID_SOCKET };
 *          create_listener (2, nFamily, sockets, IPPROTO_TCP, 9000);
 *          // ...
 *          for (auto sock : sockets) {
 *              close_socket(sock, true, 0);
 *          }
 */
return_t create_listener(unsigned int size_vector, unsigned int* vector_family, socket_t* vector_socket, int protocol_type, uint32 port,
                         bool support_win32_acceptex = false);
/**
 * @brief   create_socket and connect_socket_addr
 * @param   socket_t*   socket  [out]
 * @param   const char* address [in]
 * @param   uint16      port    [in]
 * @param   uint32      timeout [in] second
 * @error   error code (see error.hpp)
 */
return_t connect_socket(socket_t* socket, const char* address, uint16 port, uint32 timeout);
/**
 * @brief   connect to address
 * @param   socket_t            sock        [in]
 * @param   const sockaddr*     addr        [in]
 * @param   socklen_t           addrlen     [in]
 * @param   uint32              timeout     [in]
 */
return_t connect_socket_addr(socket_t sock, const sockaddr* addr, socklen_t addrlen, uint32 timeout);
/**
 * @brief   disconnect
 * @param   socket_t    sock    [in]
 * @param   bool        onoff   [in]
 * @param   uint16      linger  [in]
 */
return_t close_socket(socket_t sock, bool onoff, uint16 linger);

enum SOCK_WAIT_FLAGS {
    SOCK_WAIT_READABLE = 1 << 0,
    SOCK_WAIT_WRITABLE = 1 << 1,
};
/**
 * @brief   wait
 * @param   socket_t    sock            [in]
 * @param   uint32      milliSeconds    [in]
 * @param   uint32      flags           [in] see SOCK_WAIT_FLAGS
 */
return_t wait_socket(socket_t sock, uint32 milliSeconds, uint32 flags);

return_t set_sock_nbio(socket_t sock, uint32 nbio_mode);

/**
 * @brief   sockaddr_storage
 * @param   sockaddr_storage_t* storage [out]
 * @param   const char* address [in]
 * @param   uint16 port [in]
 */
return_t addr_to_sockaddr(sockaddr_storage_t* storage, const char* address, uint16 port);
void sockaddr_string(const sockaddr_storage_t& addr, std::string& address);

/**
 * @brief   type of socket
 * @param   socket_t sock [in]
 * @param   int& type [out]
 * @sample
 *          int socktype = 0;
 *          typeof_socket(listenfd, socktype);
 *          bool is_stream = (SOCK_STREAM == socktype);
 *          bool is_dgram = (SOCK_DGRAM == socktype);
 */
return_t typeof_socket(socket_t sock, int& type);

#if defined _WIN32 || defined _WIN64
return_t winsock_startup();
void winsock_cleanup();
#endif

class socket_advisor {
   public:
    static socket_advisor* get_instance();
    std::string nameof_family(int code);
    std::string nameof_type(int code);
    std::string nameof_protocol(int code);

   protected:
    socket_advisor();
    void build();

   private:
    static socket_advisor _instance;

    critical_section _lock;
    std::map<int, std::string> _family;
    std::map<int, std::string> _type;
    std::map<int, std::string> _protocol;
};

}  // namespace io
}  // namespace hotplace

#endif
