/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  RFC 2068 Hypertext Transfer Protocol -- HTTP/1.1
 *  RFC 2616 Hypertext Transfer Protocol -- HTTP/1.1
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/net/http/http2/http2_frame.hpp>
#include <hotplace/sdk/net/http/http_resource.hpp>

namespace hotplace {
namespace net {

http_resource http_resource::_instance;

http_resource* http_resource::get_instance() {
    _instance.load_resources();
    return &_instance;
}

http_resource::http_resource() {}

void http_resource::load_resources() {
    if (_status_codes.empty()) {
        critical_section_guard guard(_lock);
        if (_status_codes.empty()) {
            doload_resources();
        }
    }
}

void http_resource::doload_resources() {
    doload_resources_h1();
    doload_resources_h2();
    doload_resources_h3();
}

std::string http_resource::load(int status) {
    std::string message;
    t_maphint<int, std::string> hint(_status_codes);
    hint.find(status, &message);
    return message;
}

}  // namespace net
}  // namespace hotplace
