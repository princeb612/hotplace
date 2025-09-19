/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/stream/basic_stream.hpp>  // basic_stream
#include <hotplace/sdk/base/unittest/trace.hpp>
#include <hotplace/sdk/net/http/html_documents.hpp>
#include <hotplace/sdk/net/http/http2/http2_frame.hpp>
#include <hotplace/sdk/net/http/http2/http2_frame_continuation.hpp>
#include <hotplace/sdk/net/http/http2/http2_frame_push_promise.hpp>
#include <hotplace/sdk/net/http/http2/http2_protocol.hpp>
#include <hotplace/sdk/net/http/http2/http2_serverpush.hpp>
#include <hotplace/sdk/net/http/http_request.hpp>
#include <hotplace/sdk/net/http/http_resource.hpp>
#include <hotplace/sdk/net/http/http_response.hpp>
#include <hotplace/sdk/net/http/http_server.hpp>
#include <hotplace/sdk/net/server/network_session.hpp>

namespace hotplace {
namespace net {

http2_serverpush::http2_serverpush() {}

http2_serverpush &http2_serverpush::add(const char *uri, const char *file) {
    __try2 {
        if (nullptr == uri || nullptr == file) {
            __leave2;
        }
        add(std::string(uri), std::string(file));
    }
    __finally2 {}
    return *this;
}

http2_serverpush &http2_serverpush::add(const std::string &uri, const std::string &file) {
    critical_section_guard guard(_lock);
    _server_push_map.insert({uri, file});
    return *this;
}

size_t http2_serverpush::is_promised(http_request *request, http_server *server) {
    size_t ret = 0;
    __try2 {
        if (nullptr == request || nullptr == server) {
            __leave2;
        }

        if (2 != request->get_version()) {
            __leave2;
        }

        {
            auto uri = request->get_http_uri().get_uri();

            critical_section_guard guard(_lock);

            auto lbound = _server_push_map.lower_bound(uri);
            auto ubound = _server_push_map.upper_bound(uri);

            ret = std::distance(lbound, ubound);
        }
    }
    __finally2 {}
    return ret;
}

return_t http2_serverpush::push_promise(http_request *request, http_server *server, network_session *session) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == request || nullptr == server || nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (2 != request->get_version()) {
            ret = errorcode_t::bad_request;
            __leave2;
        }

        std::queue<std::string> q;
        {
            critical_section_guard guard(_lock);

            auto uri = request->get_http_uri().get_uri();
            auto lbound = _server_push_map.lower_bound(uri);
            auto ubound = _server_push_map.upper_bound(uri);
            for (auto iter = lbound; iter != ubound; iter++) {
                const auto &promise = iter->second;
                q.push(promise);
            }
        }

        auto stream_id = request->get_stream_id();
        binary_t stream;
        while (false == q.empty()) {
            const auto &promise = q.front();
            q.pop();

            do_push_promise(promise, ++stream_id, request, server, session, stream);
        }
        session->send(&stream[0], stream.size());
    }
    __finally2 {}
    return ret;
}

return_t http2_serverpush::push(http_request *request, http_server *server, network_session *session) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == request || nullptr == server || nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (2 != request->get_version()) {
            ret = errorcode_t::bad_request;
            __leave2;
        }

        std::queue<std::string> q;
        {
            critical_section_guard guard(_lock);

            auto uri = request->get_http_uri().get_uri();
            auto lbound = _server_push_map.lower_bound(uri);
            auto ubound = _server_push_map.upper_bound(uri);
            for (auto iter = lbound; iter != ubound; iter++) {
                const auto &promise = iter->second;
                q.push(promise);
            }
        }

        auto stream_id = request->get_stream_id();
        while (false == q.empty()) {
            const auto &promise = q.front();
            q.pop();

            http_response response(request);  // to refer accept-encoding
            auto test = do_push(promise, ++stream_id, request, server, session, &response);
            if (errorcode_t::success == test) {
                response.respond(session);
            }
        }
    }
    __finally2 {}
    return ret;
}

return_t http2_serverpush::do_push_promise(const std::string &promise, uint32 streamid, http_request *request, http_server *server, network_session *session,
                                           binary_t &stream) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (0 == streamid || nullptr == request || nullptr == server || nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto &htmldocs = server->get_http_router().get_html_documents();
        std::string content_type;

        ret = htmldocs.loadable(promise, content_type);  // do not load contents
        if (errorcode_t::success == ret) {
            auto &reqheader = request->get_http_header();
            auto &hpsess = session->get_http2_session()->get_hpack_dyntable();
            http_header header;
            auto method = reqheader.get(":method");
            auto scheme = reqheader.get(":scheme");
            auto authority = reqheader.get(":authority");
            header.add(":method", method).add(":path", promise).add(":scheme", scheme).add(":authority", authority);

            binary_t fragment;
            http2_frame_push_promise frame;
            frame.set_hpack_dyntable(&hpsess).set_stream_id(streamid);
            frame.write_compressed_header(&header, fragment);
            frame.set_fragment(fragment);

#if defined DEBUG
            if (istraceable(trace_category_net)) {
                basic_stream bs;
                frame.dump(&bs);
                trace_debug_event(trace_category_net, trace_event_http2_push_promise, &bs);
            }
#endif
        }
    }
    __finally2 {}
    return ret;
}

return_t http2_serverpush::do_push(const std::string &promise, uint32 streamid, http_request *request, http_server *server, network_session *session,
                                   http_response *response) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (0 == streamid || nullptr == request || nullptr == server || nullptr == session || nullptr == response) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto &htmldocs = server->get_http_router().get_html_documents();
        auto &reqheader = request->get_http_header();
        auto &hpsess = session->get_http2_session()->get_hpack_dyntable();

        std::string content_type;
        binary_t content;
        ret = htmldocs.load(promise, content_type, content);  // load contents
        if (errorcode_t::success != ret) {
            __leave2;
        }

        response->set_version(2).set_stream_id(streamid).set_hpack_dyntable(&hpsess);
        response->compose(200, content_type, content);
    }
    __finally2 {}
    return ret;
}

}  // namespace net
}  // namespace hotplace
