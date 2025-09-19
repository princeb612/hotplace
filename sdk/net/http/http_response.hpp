/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_NET_HTTP_HTTPRESPONSE__
#define __HOTPLACE_SDK_NET_HTTP_HTTPRESPONSE__

#include <hotplace/sdk/base/stream/basic_stream.hpp>  // basic_stream
#include <hotplace/sdk/net/http/http_header.hpp>      // http_header
#include <hotplace/sdk/net/http/http_router.hpp>      // http_router
#include <hotplace/sdk/net/http/types.hpp>

namespace hotplace {
namespace net {

class http_response {
    friend class http_router;

   public:
    http_response();
    http_response(http_request* request);
    http_response(const http_response& object);
    ~http_response();

    /* *
     * @brief   open HTTP 1.x
     * @param   const char*     response        [IN]
     * @param   size_t          size_response   [IN]
     * @return  error code (see error.hpp)
     */
    return_t open(const char* response, size_t size_response);
    return_t open(const char* response);
    return_t open(const basic_stream& response);
    return_t open(const std::string& response);
    /* *
     * @brief  close
     * @return  error code (see error.hpp)
     */
    return_t close();

    /**
     * @brief   compose
     */
    http_response& compose(int status_code);
    http_response& compose(int status_code, const char* content_type, const char* content, ...);
    http_response& compose(int status_code, const std::string& content_type, const char* content, ...);
    http_response& compose(int status_code, const std::string& content_type, const binary_t& bin);
    /**
     * @brief   respond
     * @example
     *          response.get_http_header().clear();
     *          response.compose(200, "text/html>", "<html><body></body></html>");
     *          basic_stream bs;
     *          response.get_response(bs)
     *          session->send((const char*)bs.data(), bs.size());
     */
    return_t respond(network_session* session);

    http_router* get_http_router();

    /**
     * @brief   Content-Type
     */
    const char* content_type();
    /**
     * @brief   content
     */
    const char* content();
    size_t content_size();
    /**
     * @brief   status code
     */
    int status_code();
    /**
     * @brief   header
     */
    http_header& get_http_header();
    /**
     * @brief   request
     */
    http_request* get_http_request();
    /**
     * @brief   response
     */
    http_response& get_response(basic_stream& bs);  // HTTP/1.1
    http_response& get_response_h2(binary_t& bin);  // HTTP/2

    virtual std::string get_version_str();

    http_response& operator=(const http_response& object);

    http_response& set_hpack_dyntable(hpack_dynamic_table* session);
    http_response& set_version(uint8 version);
    http_response& set_stream_id(uint32 stream_id);
    hpack_dynamic_table* get_hpack_dyntable();
    uint8 get_version();
    uint32 get_stream_id();

    void addref();
    void release();

   protected:
    void set_http_router(http_router* router);

    t_shared_reference<http_response> _shared;

   private:
    http_router* _router;
    http_request* _request;
    http_header _header;
    std::string _content_type;
    basic_stream _content;
    int _statuscode;

    hpack_dynamic_table* _dyntable;
    uint8 _version;
    uint32 _stream_id;
};

}  // namespace net
}  // namespace hotplace

#endif
