/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/io.hpp>
#include <sdk/net/basic/tcp_client_socket.hpp>
#include <sdk/net/basic/udp_client_socket.hpp>
#include <sdk/net/http/http_client.hpp>
#include <sdk/net/http/http_protocol.hpp>
#include <sdk/net/http/http_request.hpp>
#include <sdk/net/http/http_response.hpp>
#include <sdk/net/server/network_protocol.hpp>
#include <sdk/net/server/network_stream.hpp>
#include <sdk/net/tls/dtls_client_socket.hpp>
#include <sdk/net/tls/tls_client_socket.hpp>

namespace hotplace {
using namespace io;
namespace net {

http_client::http_client() : _socket(0), _client_socket(nullptr), _tls_context(nullptr), _tlsctx(nullptr), _wto(1000) {
    tlscert_open_simple(tlscert_flag_tls, &_tlsctx);
    _tls_client_socket = new tls_client_socket(new transport_layer_security(_tlsctx));
    _client_socket = new tcp_client_socket;
}

http_client::~http_client() {
    close();

    if (_tls_client_socket) {
        _tls_client_socket->release();
    }
    if (_client_socket) {
        delete _client_socket;
    }
    SSL_CTX_free(_tlsctx);
}

tcp_client_socket* http_client::try_connect() {
    return_t ret = errorcode_t::success;
    tcp_client_socket* client = nullptr;
    __try2 {
        if ("https" == _url_info.scheme) {
            client = _tls_client_socket;
        } else if ("http" == _url_info.scheme) {
            client = _client_socket;
        } else {
            __leave2;
        }

        if (0 == _socket) {
            ret = client->connect(&_socket, &_tls_context, _url_info.host.c_str(), _url_info.port, 5);
            if (errorcode_t::success == ret) {
                client->set_wto(_wto);
            }
        }
    }
    __finally2 {
        // do nothing
    }

    return client;
}

http_client& http_client::request(const std::string& url, http_response** response) {
    url_info_t url_info;
    split_url(url.c_str(), &url_info);

    http_request request;
    request.get_http_header().add("Host", basic_stream("%s:%i", url_info.host.c_str(), url_info.port).c_str());
    request.compose(http_method_t::HTTP_GET, url_info.uri, "");

    return do_request_and_response(url_info, request, response);
}

http_client& http_client::request(http_request& request, http_response** response) { return do_request_and_response(_url_info, request, response); }

http_client& http_client::do_request_and_response(const url_info_t& url_info, http_request& request, http_response** response) {
    return_t ret = errorcode_t::success;
    tcp_client_socket* client = nullptr;
    http_response* resp = nullptr;

    __try2 {
        if (nullptr == response) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        *response = nullptr;

        client = try_connect();

        // connected
        if (_socket) {
            basic_stream request_stream;
            request.get_request(request_stream);

            size_t cbsent = 0;
            ret = client->send(_socket, _tls_context, request_stream.c_str(), request_stream.size(), &cbsent);
            if (errorcode_t::success == ret) {
                network_protocol_group group;
                http_protocol http;
                network_stream stream_read;
                network_stream stream_interpreted;
                group.add(&http);

                std::vector<char> buf;
                const size_t bufsize = 1 << 7;
                size_t sizeread = 0;
                buf.resize(bufsize);

                ret = client->read(_socket, _tls_context, &buf[0], bufsize, &sizeread);

                stream_read.produce((byte_t*)&buf[0], sizeread);
                while (errorcode_t::more_data == ret) {
                    ret = client->more(_socket, _tls_context, &buf[0], bufsize, &sizeread);

                    stream_read.produce((byte_t*)&buf[0], sizeread);
                }

                stream_read.write(&group, &stream_interpreted);
                network_stream_data* data = nullptr;
                stream_interpreted.consume(&data);
                if (data) {
                    resp = new http_response;
                    resp->open((char*)data->content(), data->size());
                    *response = resp;

                    data->release();
                }
            }
        }
    }
    __finally2 {
        // do nothing
    }

    return *this;
}

http_client& http_client::close() {
    if (_socket) {
        _tls_client_socket->close(_socket, _tls_context);
        _socket = 0;
        _tls_context = nullptr;
    }
    return *this;
}

http_client& http_client::set_url(const std::string& url) {
    url_info_t url_info;
    split_url(url.c_str(), &url_info);

    return set_url(url_info);
}

http_client& http_client::set_url(const url_info_t& url_info) {
    if ((_url_info.scheme != url_info.scheme) || (_url_info.host != url_info.host) || (_url_info.port != url_info.port)) {
        close();
    }
    _url_info = url_info;

    return *this;
}

http_client& http_client::set_wto(uint32 milliseconds) {
    if (milliseconds) {
        _wto = milliseconds;
    }
    return *this;
}

}  // namespace net
}  // namespace hotplace
