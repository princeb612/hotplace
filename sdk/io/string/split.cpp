/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/io/string/string.hpp>

namespace hotplace {
namespace io {

return_t split_url(const char* url, url_info_t* info) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == url || nullptr == info) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        info->protocol.clear();
        info->host.clear();
        info->port = 0;
        info->uri.clear();
        info->uripath.clear();
        info->urifile.clear();

        int has_uri = 1;
        std::string input = url;
        size_t pos_protocol = 0;
        size_t pos_uri = 0;
        size_t pos_port = 0;
        size_t pos_uripath = 0;
        pos_protocol = input.find("://");

        if (std::string::npos == pos_protocol) {
            info->uri = url;
        } else {
            info->protocol.assign(url, pos_protocol);

            pos_uri = input.find_first_of("/", pos_protocol + 3);
            if (std::string::npos == pos_uri) {
                info->host = input.substr(pos_protocol + 3);
                has_uri = 0;
            } else {
                pos_port = input.find_first_of(":", pos_protocol + 3);

                if (std::string::npos == pos_port) {
                    if (0 == strcmp("https", info->protocol.c_str())) {
                        info->port = 443;
                    } else if (0 == strcmp("http", info->protocol.c_str())) {
                        info->port = 80;
                    } else if (0 == strcmp("ftp", info->protocol.c_str())) {
                        info->port = 21;
                    } else {
                        info->port = 0;
                    }

                    info->host = input.substr(pos_protocol + 3, pos_uri - pos_protocol - 3);
                } else {
                    info->host = input.substr(pos_protocol + 3, pos_port - pos_protocol - 3);
                    info->port = atoi(input.substr(pos_port + 1, pos_uri - pos_port - 1).c_str());
                }

                info->uri = input.substr(pos_uri);
            }
        }

        if (has_uri) {
            pos_uripath = input.find_last_of("/");
            if (pos_uri == pos_uripath) {
                // do nothing
            } else {
                size_t pos = 0;
                if ('/' == input[pos_uri]) {
                    pos = 1;
                }
                info->uripath = input.substr(pos_uri + pos, pos_uripath - pos_uri - 1 + (1 - pos));
            }

            if (input.size() == pos_uripath + 1) {
                // do nothing
            } else {
                info->urifile = input.substr(pos_uripath + 1);
            }
        }

        if (info->uri.empty()) {
            info->uri = "/";
        }
        if (info->uripath.empty()) {
            info->uripath = "/";
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace io
}  // namespace hotplace
