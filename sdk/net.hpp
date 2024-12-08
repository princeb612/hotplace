/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET__
#define __HOTPLACE_SDK_NET__

/* top-most */
#include <sdk/base.hpp>
#include <sdk/crypto.hpp>
#include <sdk/io.hpp>
#include <sdk/net/types.hpp>

/* basic */
#include <sdk/net/basic/client_socket.hpp>
#include <sdk/net/basic/ipaddr_acl.hpp>
#include <sdk/net/basic/server_socket.hpp>
#include <sdk/net/basic/tcp_client_socket.hpp>
#include <sdk/net/basic/tcp_server_socket.hpp>
#include <sdk/net/basic/udp_client_socket.hpp>
#include <sdk/net/basic/udp_server_socket.hpp>

/* http */
#include <sdk/net/http/html_documents.hpp>
#include <sdk/net/http/http_authentication_provider.hpp>
#include <sdk/net/http/http_authentication_resolver.hpp>
#include <sdk/net/http/http_client.hpp>
#include <sdk/net/http/http_header.hpp>
#include <sdk/net/http/http_protocol.hpp>
#include <sdk/net/http/http_request.hpp>
#include <sdk/net/http/http_resource.hpp>
#include <sdk/net/http/http_response.hpp>
#include <sdk/net/http/http_router.hpp>
#include <sdk/net/http/http_server.hpp>
#include <sdk/net/http/http_server_builder.hpp>
#include <sdk/net/http/http_uri.hpp>
#include <sdk/net/http/types.hpp>

/* http/auth */
#include <sdk/net/http/auth/basic_authentication_provider.hpp>
#include <sdk/net/http/auth/basic_credentials.hpp>
#include <sdk/net/http/auth/bearer_authentication_provider.hpp>
#include <sdk/net/http/auth/bearer_credentials.hpp>
#include <sdk/net/http/auth/custom_credentials.hpp>
#include <sdk/net/http/auth/digest_access_authentication_provider.hpp>
#include <sdk/net/http/auth/digest_credentials.hpp>
#include <sdk/net/http/auth/oauth2.hpp>
#include <sdk/net/http/auth/oauth2_credentials.hpp>
#include <sdk/net/http/auth/rfc2617_digest.hpp>

/* http/http2 */
#include <sdk/net/http/http2/hpack.hpp>
#include <sdk/net/http/http2/http2_frame.hpp>
#include <sdk/net/http/http2/http2_protocol.hpp>
#include <sdk/net/http/http2/http2_serverpush.hpp>
#include <sdk/net/http/http2/http2_session.hpp>
#include <sdk/net/http/http2/http_header_compression.hpp>

/* http/http3 */
#include <sdk/net/http/http3/qpack.hpp>

/* quic */
#include <sdk/net/quic/quic.hpp>

/* server */
#include <sdk/net/server/network_protocol.hpp>
#include <sdk/net/server/network_server.hpp>
#include <sdk/net/server/network_session.hpp>
#include <sdk/net/server/network_stream.hpp>

/* TLS */
#include <sdk/net/tls/dtls_client_socket.hpp>
#include <sdk/net/tls/dtls_server_socket.hpp>
#include <sdk/net/tls/sdk.hpp>
#include <sdk/net/tls/tls.hpp>
#include <sdk/net/tls/tls_client_socket.hpp>
#include <sdk/net/tls/tls_server_socket.hpp>
#include <sdk/net/tls/tlscert.hpp>
#include <sdk/net/tlsspec/tls.hpp>
#include <sdk/net/tlsspec/tls_advisor.hpp>

#endif
