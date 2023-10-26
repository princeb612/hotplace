/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <stdarg.h>

#include <ostream>
#include <sdk/base/basic/variant.hpp>

namespace hotplace {

return_t variant_copy(variant_t* target, const variant_t* source) {
    return_t ret = errorcode_t::success;
    variant_t* object = nullptr;

    __try2 {
        if (nullptr == target || nullptr == source) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (variant_flag_t::flag_free == source->flag) {
            switch (source->type) {
                case TYPE_BINARY:
                    variant_set_bstr_new((*target), source->data.bstr, source->size);
                    break;
                case TYPE_NSTRING:
                    variant_set_nstr_new((*target), source->data.str, source->size);
                    break;
                case TYPE_STRING:
                    variant_set_str_new((*target), source->data.str);
                    break;
                default:
                    throw;
                    break;
            }
        } else {
            memcpy(&target->data, &source->data, RTL_FIELD_SIZE(variant_t, data));
        }

        target->type = source->type;
        target->size = source->size;
        target->flag = source->flag;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t variant_move(variant_t* target, variant_t* source) {
    return_t ret = errorcode_t::success;
    variant_t* object = nullptr;

    __try2 {
        if (nullptr == target || nullptr == source) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        memcpy(target, source, sizeof(variant_t));  // copy including type and flag
        source->flag = 0;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

void variant_free(variant_t& vt) {
    if (variant_flag_t::flag_free == vt.flag) {
        switch (vt.type) {
            case TYPE_STRING:
            case TYPE_NSTRING:
            case TYPE_POINTER:
            case TYPE_BINARY:
                if (vt.data.p) {
                    free(vt.data.p);
                }
                break;
            default:
                break;
        }
    }
    variant_init(vt);
}

return_t variant_binary(variant_t const& vt, binary_t& target) {
    return_t ret = errorcode_t::success;

    if (TYPE_BINARY == vt.type) {
        target.resize(vt.size);
        memcpy(&target[0], vt.data.bstr, vt.size);
    } else {
        ret = errorcode_t::mismatch;
    }
    return ret;
}

return_t variant_string(variant_t const& vt, std::string& target) {
    return_t ret = errorcode_t::success;

    if (vt.data.str) {
        if (TYPE_STRING == vt.type) {
            target = vt.data.str;
        } else if (TYPE_NSTRING == vt.type) {
            target.assign(vt.data.str, vt.size);
        } else if (TYPE_BINARY == vt.type) {
            target.clear();
            uint32 i = 0;
            char* p = nullptr;
            for (i = 0, p = vt.data.str; i < vt.size; i++, p++) {
                if (isprint(*p)) {
                    target.append(p, 1);
                } else {
                    target.append(".");
                }
            }
        } else {
            ret = errorcode_t::mismatch;
        }
    } else {
        target.clear();
    }
    return ret;
}

}  // namespace hotplace
