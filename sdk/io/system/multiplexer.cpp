/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <map>
#include <sdk/base/system/critical_section.hpp>
#include <sdk/base/system/thread.hpp>
#include <sdk/io/system/multiplexer.hpp>

namespace hotplace {
namespace io {

#define MULTIPLEXER_EVENT_LOOP_CONTROLLER_CONTEXT_SIGNATURE 0x20151208

typedef std::map<arch_t, uint32> multiplexer_event_loop_controler_map_t;
typedef std::pair<multiplexer_event_loop_controler_map_t::iterator, bool> multiplexer_event_loop_controler_map_pib_t;

typedef struct _multiplexer_event_loop_controller_context_t : public multiplexer_controller_context_t {
    uint32 signature;
    critical_section lock;
    multiplexer_event_loop_controler_map_t control;
} multiplexer_event_loop_controller_context_t;

multiplexer_controller::multiplexer_controller() {
    // do nothing
}

multiplexer_controller::~multiplexer_controller() {
    // do nothing
}

return_t multiplexer_controller::open(multiplexer_controller_context_t** handle) {
    return_t ret = errorcode_t::success;
    multiplexer_event_loop_controller_context_t* context = nullptr;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        __try_new_catch(context, new multiplexer_event_loop_controller_context_t, ret, __leave2);

        context->signature = MULTIPLEXER_EVENT_LOOP_CONTROLLER_CONTEXT_SIGNATURE;
        *handle = context;
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t multiplexer_controller::close(multiplexer_controller_context_t* handle) {
    return_t ret = errorcode_t::success;
    multiplexer_event_loop_controller_context_t* context = static_cast<multiplexer_event_loop_controller_context_t*>(handle);

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (MULTIPLEXER_EVENT_LOOP_CONTROLLER_CONTEXT_SIGNATURE != context->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        context->signature = 0;
        delete context;
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t multiplexer_controller::event_loop_new(multiplexer_controller_context_t* handle, arch_t* token_handle) {
    return_t ret = errorcode_t::success;
    multiplexer_event_loop_controller_context_t* context = static_cast<multiplexer_event_loop_controller_context_t*>(handle);

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (MULTIPLEXER_EVENT_LOOP_CONTROLLER_CONTEXT_SIGNATURE != context->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        arch_t tid = get_thread_id();

        critical_section_guard guard(context->lock);

        multiplexer_event_loop_controler_map_pib_t pib = context->control.insert(std::make_pair(tid, 1));
        if (false == pib.second) {
            ret = errorcode_t::already_exist;
        }

        if (nullptr != token_handle) {
            *token_handle = tid;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t multiplexer_controller::event_loop_break(multiplexer_controller_context_t* handle, arch_t* token_handle) {
    return_t ret = errorcode_t::success;
    multiplexer_event_loop_controller_context_t* context = static_cast<multiplexer_event_loop_controller_context_t*>(handle);

    multiplexer_event_loop_controler_map_t::iterator iter;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (MULTIPLEXER_EVENT_LOOP_CONTROLLER_CONTEXT_SIGNATURE != context->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        /* signal */

        critical_section_guard guard(context->lock);

        if (nullptr == token_handle) {
            for (iter = context->control.begin(); iter != context->control.end(); iter++) {
                iter->second = 0;
            }
        } else {
            iter = context->control.find(*token_handle);
            if (context->control.end() != iter) {
                iter->second = 0;
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t multiplexer_controller::event_loop_break_concurrent(multiplexer_controller_context_t* handle, size_t concurrent) {
    return_t ret = errorcode_t::success;
    multiplexer_event_loop_controller_context_t* context = static_cast<multiplexer_event_loop_controller_context_t*>(handle);

    multiplexer_event_loop_controler_map_t::iterator iter;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (MULTIPLEXER_EVENT_LOOP_CONTROLLER_CONTEXT_SIGNATURE != context->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        /* signal */

        size_t i = 0;
        critical_section_guard guard(context->lock);
        for (iter = context->control.begin(); iter != context->control.end(); iter++) {
            if (i >= concurrent) {
                break;
            }
            if (iter->second) {
                iter->second = 0;
                i++;
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

bool multiplexer_controller::event_loop_test_broken(multiplexer_controller_context_t* handle, arch_t token_handle) {
    bool ret_value = false;
    // return_t ret = errorcode_t::success;
    multiplexer_event_loop_controller_context_t* context = static_cast<multiplexer_event_loop_controller_context_t*>(handle);

    multiplexer_event_loop_controler_map_t::iterator iter;

    __try2 {
        critical_section_guard guard(context->lock);
        iter = context->control.find(token_handle);
        if (context->control.end() != iter) {
            if (0 == iter->second) {
                ret_value = true;
            }
        } else {
            ret_value = true;
        }
    }
    __finally2 {
        // do nothing
    }

    return ret_value;
}

return_t multiplexer_controller::event_loop_close(multiplexer_controller_context_t* handle, arch_t token_handle) {
    return_t ret = errorcode_t::success;
    multiplexer_event_loop_controller_context_t* context = static_cast<multiplexer_event_loop_controller_context_t*>(handle);

    __try2 {
        multiplexer_event_loop_controler_map_t::iterator iter;

        critical_section_guard guard(context->lock);
        iter = context->control.find(token_handle);
        if (context->control.end() != iter) {
            context->control.erase(iter);
        }
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

}  // namespace io
}  // namespace hotplace
