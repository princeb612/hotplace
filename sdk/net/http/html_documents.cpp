/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base.hpp>
#include <sdk/base/inline.hpp>
#include <sdk/base/string/string.hpp>
#include <sdk/base/system/critical_section.hpp>
#include <sdk/io/basic/zlib.hpp>
#include <sdk/io/stream/file_stream.hpp>
#include <sdk/io/string/string.hpp>
#include <sdk/net/basic/sdk.hpp>
#include <sdk/net/http/html_documents.hpp>
#include <sdk/net/http/http_router.hpp>
#include <sdk/net/tls/tls.hpp>

namespace hotplace {
using namespace io;
namespace net {

html_documents::html_documents() : _use(false) {}

html_documents::html_documents(std::string const& root_uri, std::string const& directory) : _use(false) { add_documents_root(root_uri, directory); }

bool html_documents::test() { return _use; }

html_documents& html_documents::add_documents_root(std::string const& root_uri, std::string const& directory) {
    critical_section_guard guard(_lock);

    // concat /
    std::string turi = root_uri;
    if (false == ends_with(turi, "/")) {
        turi += "/";
    }
    // concat / (linux) or \\ (windows)
    std::string tdir = directory;
    if (false == ends_with(tdir, DIR_SEP_T)) {
        tdir += DIR_SEP_T;
    }
    _root.insert(std::make_pair(turi, tdir));

    _use = true;

    return *this;
}

html_documents& html_documents::add_content_type(std::string const& dot_ext, std::string const& content_type) {
    critical_section_guard guard(_lock);
    _content_types.insert(std::make_pair(dot_ext, content_type));
    return *this;
}

html_documents& html_documents::set_default_document(std::string const& document) {
    _document = document;
    return *this;
}

bool html_documents::map(std::string const& uri, std::string& local) {
    bool ret_value = false;

    local.clear();

    critical_section_guard guard(_lock);
    for (auto item : _root) {
        size_t pos = uri.find(item.first);
        if (std::string::npos != pos) {
            local = uri;
            replace(local, item.first, item.second);
            if (ends_with(uri, "/")) {
                local += _document;  // index.html
            }
            ret_value = true;
            break;
        }
    }

    return ret_value;
}

return_t html_documents::load(std::string const& uri, std::string& content_type, binary_t& content) {
    return_t ret = errorcode_t::success;
    __try2 {
        // todo compare timestamp

        get_content_type(uri, content_type);

        // search from cache
        ret = search_cache(uri, content);
        if (errorcode_t::success == ret) {
            __leave2;
        }

        // if not found, try to read from file
        ret = loadfile(uri, content);
        if (errorcode_t::success == ret) {
            insert_cache(uri, content);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t html_documents::handler(std::string const& uri, network_session* session, http_request* request, http_response* response) {
    return_t ret = errorcode_t::success;
    if (test()) {
        std::string content_type;
        binary_t content;
        ret = load(uri, content_type, content);
        if (errorcode_t::success == ret) {
            response->compose(200, content_type, "%.*s", (unsigned)content.size(), &content[0]);
        }
    } else {
        ret = errorcode_t::not_available;
    }
    return ret;
}

return_t html_documents::search_cache(std::string const& uri, binary_t& content) {
    return_t ret = errorcode_t::success;
    critical_section_guard guard(_lock);
    std::map<std::string, binary_t>::iterator iter = _cache_map.find(uri);
    if (_cache_map.end() != iter) {
        content = iter->second;
    } else {
        ret = errorcode_t::not_found;
    }
    return ret;
}

return_t html_documents::insert_cache(std::string const& uri, binary_t& content) {
    return_t ret = errorcode_t::success;
    critical_section_guard guard(_lock);
    _cache_map.insert(std::make_pair(uri, content));
    return ret;
}

return_t html_documents::loadfile(std::string const& uri, binary_t& content) {
    return_t ret = errorcode_t::success;

    content.clear();

    std::string local;
    if (map(uri, local)) {
        file_stream fs;
        ret = fs.open(local.c_str());
        if (errorcode_t::success == ret) {
            fs.begin_mmap();
            content.insert(content.end(), fs.data(), fs.data() + fs.size());
        }
    } else {
        ret = errorcode_t::not_found;
    }

    return ret;
}

return_t html_documents::get_content_type(std::string const& uri, std::string& content_type) {
    return_t ret = errorcode_t::success;
    critical_section_guard guard(_lock);

    size_t pos = uri.find_last_of(".");
    if (std::string::npos != pos) {
        std::string dot_ext = uri.substr(pos);

        std::map<std::string, std::string>::iterator iter = _content_types.find(dot_ext);
        if (_content_types.end() != iter) {
            content_type = iter->second;
        } else {
            ret = errorcode_t::not_found;
        }
    } else {
        ret = errorcode_t::not_found;
    }
    return ret;
}

}  // namespace net
}  // namespace hotplace
