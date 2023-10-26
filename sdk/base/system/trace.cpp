/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/system/trace.hpp>

namespace hotplace {

static uint32 _trace_option = 0;

uint32 set_trace_option(uint32 option) {
    uint32 old_option = _trace_option;

    _trace_option = option;

    if (trace_option_t::trace_except & old_option) {
        if (0 == (trace_option_t::trace_except & option)) {
            reset_trace_exception();
        }
    } else {
        if (trace_option_t::trace_except & option) {
            set_trace_exception();
        }
    }
    return old_option;
}

uint32 get_trace_option() { return _trace_option; }

}  // namespace hotplace
