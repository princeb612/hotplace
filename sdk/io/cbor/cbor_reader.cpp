/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2023.09.01   Soo Han, Kim        refactor
 */

#include <hotplace/sdk/io/basic/base16.hpp>
#include <hotplace/sdk/io/cbor/cbor.hpp>
#include <hotplace/sdk/io/system/types.hpp>

namespace hotplace {
namespace io {

cbor_reader::cbor_reader ()
{
    // do nothing
}

return_t cbor_reader::open (cbor_reader_context_t** handle)
{
    return_t ret = errorcode_t::success;
    cbor_reader_context_t* context = nullptr;

    __try2
    {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        __try_new_catch (context, new cbor_reader_context_t, ret, __leave2);
        *handle = context;
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t cbor_reader::close (cbor_reader_context_t* handle)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (handle->root) {
            handle->root->release ();
        }

        delete handle;
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t cbor_reader::parse (cbor_reader_context_t* handle, const char* expr)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == handle || nullptr == expr) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        binary_t bin;

        bin = base16_decode (expr);
        ret = parse (handle, bin);
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t cbor_reader::parse (cbor_reader_context_t* handle, binary_t const& expression)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        size_t i = 0;
        size_t size = expression.size ();
        const byte_t* data = &expression[0];
        uint32 flags = 0;
        byte_t cur = 0;
        uint32 tag = 0;

        if (handle->root) {
            handle->root->release ();
            handle->root = nullptr;
        }

        for (i < 0; i < size; i++) {
            cur = *(data + i);

            byte_t lead_type = (cur & 0xe0) >> 5;
            byte_t lead_value = (cur & 0x1f);
            int128 value = lead_value;
            flags = 0;

            // cbor_simple_t::cbor_simple_break
            if ((0xff == cur) && handle->indef) {
                handle->indef--;
                handle->parents.pop_back ();
                continue;
            }

            // including cbor_major_t::cbor_major_tag
            if (lead_value >= 24) {
                if (24 == lead_value) {
                    value = *(byte_t*) (data + i + 1);
                    i++;
                } else if (25 == lead_value) {
                    value = *(uint16*) (data + i + 1);
                    value = ntohs (value);
                    i += 2;
                } else if (26 == lead_value) {
                    value = *(uint32*) (data + i + 1);
                    value = ntohl (value);
                    i += 4;
                } else if (27 == lead_value) {
                    value = *(uint64*) (data + i + 1);
                    value = ntoh64 (value);
                    i += 8;
                } else if (31 == lead_value) {
                    handle->indef++;
                    flags = cbor_flag_t::cbor_indef;
                }
            }

            if (cbor_major_t::cbor_major_uint == lead_type) {
                push (handle, lead_type, value, 0);
            } else if (cbor_major_t::cbor_major_nint == lead_type) {
                push (handle, lead_type, -((int128) value + 1), 0);
            } else if (cbor_major_t::cbor_major_bstr == lead_type) {
                push (handle, lead_type, (byte_t*) data + i + 1, value, flags);
                if (0 == (cbor_flag_t::cbor_indef & flags)) {
                    i += value;
                }
            } else if (cbor_major_t::cbor_major_tstr == lead_type) {
                push (handle, lead_type, (char*) data + i + 1, value, flags);
                if (0 == (cbor_flag_t::cbor_indef & flags)) {
                    i += value;
                }
            } else if ((cbor_major_t::cbor_major_array == lead_type) || (cbor_major_t::cbor_major_map == lead_type)) {
                push (handle, lead_type, value, flags);
            } else if (cbor_major_t::cbor_major_tag == lead_type) {
                handle->tag_value = value;
                handle->tag_flag = true;
                continue;
            } else if (cbor_major_t::cbor_major_simple == lead_type) {
                // to do
                //
                // Single Precision
                // Positive Infinity: 7F800000
                // Negative Infinity: FF800000
                // Signaling NaN: 7F8000001~ 7FBFFFFF or FF800001 ~ FFBFFFFF
                // Quiet NaN: 7FC00000 ~ 7FFFFFFF or FFC00000 ~ FFFFFFFF
                //
                // Double Precision
                // Positive Infinity: 7FF0000000000000
                // Negative Infinity: FFF0000000000000
                // Signaling NaN: 7FF0000000000001 ~ 7FF7FFFFFFFFFFFF or FFF0000000000001 ~ FFF7FFFFFFFFFFFF
                // Quiet NaN: 7FF8000000000000 ~ 7FFFFFFFFFFFFFFF or FFF8000000000000 ~ FFFFFFFFFFFFFFFF
                cbor_simple_t simple_type = cbor_simple::is_kind_of (cur);
                switch (simple_type) {
                    case cbor_simple_t::cbor_simple_single_fp:
                        push (handle, lead_type, (float) value, 0);
                        break;
                    case cbor_simple_t::cbor_simple_double_fp:
                        push (handle, lead_type, (double) value, 0);
                        break;
                    default:
                        push (handle, lead_type, value, 0);
                        break;
                }
            }

            handle->tag_value = 0;
            handle->tag_flag = false;
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t cbor_reader::push (cbor_reader_context_t* handle, uint8 type, int128 data, uint32 flags)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (cbor_major_t::cbor_major_uint == type) {
            cbor_data* temp = nullptr;
            __try_new_catch (temp, new cbor_data (data), ret, __leave2);
            temp->tag (handle->tag_flag, (cbor_tag_t) handle->tag_value);
            insert (handle, temp);
        } else if (cbor_major_t::cbor_major_nint == type) {
            cbor_data* temp = nullptr;
            __try_new_catch (temp, new cbor_data (data), ret, __leave2);
            temp->tag (handle->tag_flag, (cbor_tag_t) handle->tag_value);
            insert (handle, temp);
        } else if (cbor_major_t::cbor_major_array == type) {
            cbor_array* temp = nullptr;
            __try_new_catch (temp, new cbor_array (flags), ret, __leave2);
            temp->tag (handle->tag_flag, (cbor_tag_t) handle->tag_value);
            if (0 == flags) {
                temp->reserve (data);
            }
            insert (handle, temp);
        } else if (cbor_major_t::cbor_major_map == type) {
            cbor_map* temp = nullptr;
            __try_new_catch (temp, new cbor_map (flags), ret, __leave2);
            temp->tag (handle->tag_flag, (cbor_tag_t) handle->tag_value);
            if (0 == flags) {
                temp->reserve (data);
            }
            insert (handle, temp);
        } else if (cbor_major_t::cbor_major_tag == type) {
        } else if (cbor_major_t::cbor_major_simple == type) {
            cbor_simple* temp = nullptr;
            __try_new_catch (temp, new cbor_simple (data), ret, __leave2);
            temp->tag (handle->tag_flag, (cbor_tag_t) handle->tag_value);
            insert (handle, temp);
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t cbor_reader::push (cbor_reader_context_t* handle, uint8 type, const char* data, size_t size, uint32 flags)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (cbor_major_t::cbor_major_tstr == type) {
            if (cbor_flag_t::cbor_indef & flags) {
                cbor_tstrings* temp = nullptr;
                __try_new_catch (temp, new cbor_tstrings (), ret, __leave2);
                insert (handle, temp);
            } else {
                cbor_data* temp = nullptr;
                __try_new_catch (temp, new cbor_data (data, size), ret, __leave2);
                temp->tag (handle->tag_flag, (cbor_tag_t) handle->tag_value);
                insert (handle, temp);
            }
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t cbor_reader::push (cbor_reader_context_t* handle, uint8 type, const byte_t* data, size_t size, uint32 flags)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (cbor_major_t::cbor_major_bstr == type) {
            if (cbor_flag_t::cbor_indef & flags) {
                cbor_bstrings* temp = nullptr;
                __try_new_catch (temp, new cbor_bstrings (), ret, __leave2);
                insert (handle, temp);
            } else {
                cbor_data* temp = nullptr;
                __try_new_catch (temp, new cbor_data (data, size), ret, __leave2);
                temp->tag (handle->tag_flag, (cbor_tag_t) handle->tag_value);
                insert (handle, temp);
            }
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t cbor_reader::push (cbor_reader_context_t* handle, uint8 type, float data, size_t size)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (cbor_major_t::cbor_major_float == type) {
            cbor_data* temp = nullptr;
            __try_new_catch (temp, new cbor_data (data), ret, __leave2);
            temp->tag (handle->tag_flag, (cbor_tag_t) handle->tag_value);
            insert (handle, temp);
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t cbor_reader::push (cbor_reader_context_t* handle, uint8 type, double data, size_t size)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (cbor_major_t::cbor_major_float == type) {
            cbor_data* temp = nullptr;
            __try_new_catch (temp, new cbor_data (data), ret, __leave2);
            temp->tag (handle->tag_flag, (cbor_tag_t) handle->tag_value);
            insert (handle, temp);
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t cbor_reader::insert (cbor_reader_context_t* handle, cbor_object* object)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == handle || nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (nullptr == handle->root) {
            handle->root = object;
        }

        cbor_object* parent = nullptr;
        if (handle->parents.size ()) {
            parent = handle->parents.back ();
        }

        cbor_type_t type = object->type ();

        if (parent) {
            if (cbor_type_t::cbor_type_map == parent->type ()) {
                handle->items.push_back (object);
                if (handle->items.size () >= 2) {
                    cbor_object* lhs = handle->items.at (0);
                    cbor_object* rhs = handle->items.at (1);
                    ret = parent->join (lhs, rhs);
                    if (errorcode_t::success == ret) {
                        handle->items.pop_front ();
                        handle->items.pop_front ();
                    }
                }
            } else {
                ret = parent->join (object);
            }
        }

        switch (type) {
            case cbor_type_t::cbor_type_array:
            case cbor_type_t::cbor_type_map:
            case cbor_type_t::cbor_type_bstrs:
            case cbor_type_t::cbor_type_tstrs:
                handle->parents.push_back (object);
                break;
            default:
                if (parent) {
                    if (is_enough (parent)) {
                        handle->parents.pop_back ();
                    }
                }
                break;
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

bool cbor_reader::is_enough (cbor_object* object)
{
    bool ret = false;

    if (object) {
        uint32 flags = object->get_flags ();
        if (0 == (cbor_flag_t::cbor_indef & flags)) {
            size_t capacity = object->capacity ();
            size_t size = object->size ();

            if (capacity == size) {
                ret = true;
            }
        }
    }
    return ret;
}

return_t cbor_reader::publish (cbor_reader_context_t* handle, stream_t* stream)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == handle || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        cbor_publisher publisher;

        publisher.publish (handle->root, stream);
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t cbor_reader::publish (cbor_reader_context_t* handle, binary_t& bin)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        cbor_publisher publisher;

        publisher.publish (handle->root, &bin);
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

}
}
