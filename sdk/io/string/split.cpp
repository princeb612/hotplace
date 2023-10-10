/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/io/string/string.hpp>

namespace hotplace {
namespace io {

return_t split_begin(split_context_t** handle, const char* str, const char* delim) {
    return_t ret = errorcode_t::success;
    split_context_t* context = nullptr;

    __try2 {
        if (nullptr == handle || nullptr == str || nullptr == delim) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        __try_new_catch(context, new split_context_t, ret, __leave2);

        context->source = str;

        size_t begin = 0;
        size_t end = strlen(str);
        size_t mark = 0;
        size_t size_delim = strlen(delim);
        split_map_item item;
        for (;;) {
            mark = context->source.find_first_of(delim, begin);
            if ((size_t)-1 == mark) {
                item.begin = begin;
                item.length = end - begin;
                if (item.length) {
                    context->info.push_back(item);
                }
                break;
            } else {
                item.begin = begin;
                item.length = mark - begin;
                context->info.push_back(item);
                begin = (mark + size_delim);
            }
        }
        *handle = context;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t split_count(split_context_t* handle, size_t& result) {
    return_t ret = errorcode_t::success;

    __try2 {
        result = 0;
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        result = handle->info.size();
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t split_get(split_context_t* handle, unsigned int index, binary_t& data) {
    return_t ret = errorcode_t::success;

    __try2 {
        data.clear();
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (index >= handle->info.size()) {
            ret = errorcode_t::out_of_range;
            __leave2;
        }

        split_map_list::iterator it = handle->info.begin();
        std::advance(it, index);

        split_map_item& item = *it;
        data.resize(item.length);
        memcpy(&data[0], handle->source.c_str() + item.begin, item.length);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t split_get(split_context_t* handle, unsigned int index, std::string& data) {
    return_t ret = errorcode_t::success;

    __try2 {
        data.clear();
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (index >= handle->info.size()) {
            ret = errorcode_t::out_of_range;
            __leave2;
        }

        split_map_list::iterator it = handle->info.begin();
        std::advance(it, index);

        split_map_item& item = *it;
        data.assign(handle->source.c_str() + item.begin, item.length);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t split_end(split_context_t* handle) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        delete handle;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t split_url(const char* url, url_info_t* info) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == url || nullptr == info) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        info->protocol.clear();
        info->domainip.clear();
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
                info->domainip = input.substr(pos_protocol + 3);
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

                    info->domainip = input.substr(pos_protocol + 3, pos_uri - pos_protocol - 3);
                } else {
                    info->domainip = input.substr(pos_protocol + 3, pos_port - pos_protocol - 3);
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
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace io
}  // namespace hotplace
