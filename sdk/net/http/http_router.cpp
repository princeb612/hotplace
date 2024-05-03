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
#include <sdk/io.hpp>
#include <sdk/net/http/http_resource.hpp>
#include <sdk/net/http/http_router.hpp>

namespace hotplace {
using namespace io;
namespace net {

http_router::http_router() {}

http_router::~http_router() { clear(); }

void http_router::clear() {
    for (authenticate_map_t::iterator iter = _authenticate_map.begin(); iter != _authenticate_map.end(); iter++) {
        http_authenticate_provider* provider = iter->second;
        provider->release();
    }
    _authenticate_map.clear();
}

http_router& http_router::add(const char* uri, http_request_handler_t handler, http_authenticate_provider* auth_provider, bool upref) {
    if (uri) {
        add(std::string(uri), handler, auth_provider, upref);
    }
    return *this;
}

http_router& http_router::add(const char* uri, http_request_function_t handler, http_authenticate_provider* auth_provider, bool upref) {
    if (uri) {
        add(std::string(uri), handler, auth_provider, upref);
    }
    return *this;
}

http_router& http_router::add(const std::string& uri, http_request_handler_t handler, http_authenticate_provider* auth_provider, bool upref) {
    critical_section_guard guard(_lock);

    http_router_t route;
    route.handler = handler;
    _handler_map.insert(std::make_pair(uri, route));

    if (auth_provider) {
        authenticate_map_pib_t pib = _authenticate_map.insert(std::make_pair(uri, auth_provider));
        if (upref) {
            if (pib.second) {
                auth_provider->addref();
            }
        }
    }

    return *this;
}

http_router& http_router::add(const std::string& uri, http_request_function_t handler, http_authenticate_provider* auth_provider, bool upref) {
    critical_section_guard guard(_lock);

    http_router_t route;
    route.stdfunc = handler;
    _handler_map.insert(std::make_pair(uri, route));

    if (auth_provider) {
        authenticate_map_pib_t pib = _authenticate_map.insert(std::make_pair(uri, auth_provider));
        if (upref) {
            if (pib.second) {
                auth_provider->addref();
            }
        }
    }

    return *this;
}

http_router& http_router::add(int status_code, http_request_handler_t handler) {
    critical_section_guard guard(_lock);
    http_router_t route;
    route.handler = handler;
    _status_handler_map.insert(std::make_pair(status_code, route));
    return *this;
}

http_router& http_router::add(int status_code, http_request_function_t handler) {
    critical_section_guard guard(_lock);
    http_router_t route;
    route.stdfunc = handler;
    _status_handler_map.insert(std::make_pair(status_code, route));
    return *this;
}

return_t http_router::route(network_session* session, http_request* request, http_response* response) {
    return_t ret = errorcode_t::success;
    http_authenticate_provider* provider = nullptr;

    __try2 {
        if (nullptr == request || nullptr == response) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        get_auth_provider(request, response, &provider);
        if (provider) {
            bool test = get_authenticate_resolver().resolve(provider, session, request, response);
            if (false == test) {
                provider->request_auth(session, request, response);
                __leave2;
            }
        }

        http_router_t routing;
        {
            critical_section_guard guard(_lock);

            std::function<void(http_router_t&)> route_not_found = [&](http_router_t& route) -> void {
                status_handler_map_t::iterator status_iter = _status_handler_map.find(404);
                if (_status_handler_map.end() != status_iter) {
                    route = status_iter->second;
                }
            };

            const char* uri = request->get_http_uri().get_uripath();

            handler_map_t::iterator iter = _handler_map.find(uri);
            if (_handler_map.end() != iter) {
                routing = iter->second;
            } else if (get_html_documents().test()) {
                return_t check = get_html_documents().handler(uri, session, request, response);
                if (errorcode_t::success == check) {
                    __leave2;
                } else {
                    route_not_found(routing);
                }
            } else {
                route_not_found(routing);
            }
        }

        if (routing.handler) {
            (*routing.handler)(session, request, response, this);
        } else if (routing.stdfunc) {
            routing.stdfunc(session, request, response, this);
        } else {
            status404_handler(session, request, response, this);
        }
    }
    __finally2 {
        if (provider) {
            provider->release();
        }
    }

    return ret;
}

void http_router::status404_handler(network_session* session, http_request* request, http_response* response, http_router* router) {
    http_resource* resource = http_resource::get_instance();
    int status_code = 404;
    response->compose(status_code, "text/html", "<html><body>%i %s</body></html>", status_code, resource->load(status_code).c_str());
}

http_authentication_resolver& http_router::get_authenticate_resolver() { return _resolver; }

html_documents& http_router::get_html_documents() { return _http_documents; }

oauth2_provider& http_router::get_oauth2_provider() { return _oauth2; }

bool http_router::get_auth_provider(http_request* request, http_response* response, http_authenticate_provider** provider) {
    bool ret_value = false;
    return_t ret = errorcode_t::success;
    http_authenticate_provider* auth_provider = nullptr;

    __try2 {
        if (nullptr == request || nullptr == response || nullptr == provider) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        } else {
            critical_section_guard guard(_lock);

            std::string uri = request->get_http_uri().get_uripath();

            for (authenticate_map_t::iterator iter = _authenticate_map.begin(); iter != _authenticate_map.end(); iter++) {
                std::string root_uri = iter->first;
                if (root_uri == uri) {
                    auth_provider = iter->second;
                    break;
                }
            }
        }

        if (nullptr == auth_provider) {
            ret = errorcode_t::not_found;
            __leave2;
        } else {
            auth_provider->addref();
            *provider = auth_provider;
            ret_value = true;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret_value;
}

}  // namespace net
}  // namespace hotplace
