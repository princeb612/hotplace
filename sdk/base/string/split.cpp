/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/string/string.hpp>

namespace hotplace {

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
    __finally2 {}
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
    __finally2 {}
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

        const split_map_item& item = handle->info[index];
        data.resize(item.length);
        if (item.length) {
            memcpy(&data[0], handle->source.c_str() + item.begin, item.length);
        }
    }
    __finally2 {}
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

        const split_map_item& item = handle->info[index];
        data.assign(handle->source.c_str() + item.begin, item.length);
    }
    __finally2 {}
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
    __finally2 {}
    return ret;
}

return_t split_foreach(split_context_t* handle, std::function<void(const std::string&)> func) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == handle || nullptr == func) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        for (const auto& item : handle->info) {
            std::string data;
            data.assign(handle->source.c_str() + item.begin, item.length);
            func(data);
        }
    }
    __finally2 {}
    return ret;
}

}  // namespace hotplace
