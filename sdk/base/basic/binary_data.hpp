/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_BASIC_BINARYDATA__
#define __HOTPLACE_SDK_BASE_BASIC_BINARYDATA__

#include <string.h>

#include <functional>
#include <sdk/base/basic/binary.hpp>
#include <sdk/base/nostd/template.hpp>

namespace hotplace {

enum binary_flag_t {
    bin_trunc = 1,  //
};

template <typename T, typename RANGETYPE = int>
class t_binary_data {
   public:
    t_binary_data() {}

    void assign(T type, const byte_t* stream, size_t size) {
        critical_section_guard guard(_lock);
        auto& entry = _map[type];
        entry.part.clear();
        entry.bin.clear();
        if (stream) {
            entry.part.add(0, size);
            entry.bin.insert(entry.bin.end(), stream, stream + size);
        }
    }
    void assign(T type, const binary_t& bin) { assign(type, &bin[0], bin.size()); }
    void append(T type, const byte_t* stream, size_t size) {
        if (stream) {
            critical_section_guard guard(_lock);
            auto& entry = _map[type];
            auto binsize = entry.bin.size();
            entry.part.add(binsize, binsize + size);
            entry.bin.insert(entry.bin.end(), stream, stream + size);
        }
    }
    void append(T type, const binary_t& bin) { append(type, &bin[0], bin.size()); }
    return_t write(T type, size_t offset, const byte_t* stream, size_t size) {
        return_t ret = errorcode_t::success;
        if (stream) {
            critical_section_guard guard(_lock);
            auto& entry = _map[type];
            entry.part.add(offset, offset + size);
            auto binsize = entry.bin.size();
            if (binsize < (offset + size)) {
                entry.bin.resize(offset + size);
            }
            memcpy(&entry.bin[offset], stream, size);

        } else {
            ret = errorcode_t::invalid_parameter;
        }
        return ret;
    }
    return_t write(T type, size_t offset, const binary_t& bin) { return write(type, offset, &bin[0], bin.size()); }
    const binary_t& get(T type) { return _map[type].bin; }
    void erase(T type) {
        critical_section_guard guard(_lock);
        auto iter = _map.find(type);
        if (_map.end() != iter) {
            _map.erase(iter);
        }
    }
    void clear() { _map.clear(); }
    bool isfragmented(T type) {
        bool ret = false;
        critical_section_guard guard(_lock);
        auto iter = _map.find(type);
        if (_map.end() != iter) {
            auto& part = iter->second.part;
            auto res = part.merge();
            if (res.size() > 1) {
                ret = true;
            }
        }
        return ret;
    }

    /**
     * @param   T type [in]
     * @param   const byte_t* stream [in]
     * @param   size_t size [in]
     * @param   uint32 flags [inopt]
     */
    return_t produce(T type, const byte_t* stream, size_t size, uint32 flags = 0) {
        return_t ret = errorcode_t::success;
        if (bin_trunc & flags) {
            assign(type, stream, size);
        } else {
            append(type, stream, size);
        }
        return ret;
    }
    /**
     * @param   T type [in]
     * @param   const binary_t& bin [in]
     * @param   uint32 flags [inopt]
     */
    return_t produce(T type, const binary_t& bin, uint32 flags = 0) {
        return_t ret = errorcode_t::success;
        if (bin_trunc & flags) {
            assign(type, bin);
        } else {
            append(type, bin);
        }
        return ret;
    }
    /**
     * @param   T type [in]
     * @param   size_t offset [in]
     * @param   const byte_t* stream [in]
     * @param   size_t size [in]
     * @param   uint32 flags [inopt]
     */
    return_t produce(T type, size_t offset, const byte_t* stream, size_t size) { return write(type, offset, stream, size); }
    /**
     * @param   T type [in]
     * @param   size_t offset [in]
     * @param   const binary_t& bin [in]
     */
    return_t produce(T type, size_t offset, const binary_t& bin) { return write(type, offset, &bin[0], bin.size()); }

    /**
     * @param   T type [in]
     * @param   size_t offset [in]
     * @param   size_t size [in]
     * @param   std::function<void(const byte_t*, size_t)> func [inopt]
     */
    return_t consume(T type, size_t offset, size_t size, std::function<void(const byte_t*, size_t)> func = nullptr) {
        return_t ret = errorcode_t::success;
        __try2 {
            critical_section_guard guard(_lock);
            auto iter = _map.find(type);
            if (_map.end() == iter) {
                ret = errorcode_t::not_found;
                __leave2;
            } else {
                auto& part = iter->second.part;
                auto& data = iter->second.bin;
                if (offset + size < data.size()) {
                    ret = errorcode_t::insufficient_buffer;
                    __leave2;
                } else {
                    if (func) {
                        func(&data[offset], size);
                    }

                    data.erase(data.begin() + offset, data.begin() + offset + size);

                    if (data.empty()) {
                        _map.erase(iter);
                    } else {
                        part.subtract(offset, offset + size);
                    }
                }
            }
        }
        __finally2 {}
        return ret;
    }
    /**
     * @param   T type [in]
     */
    return_t consume(T type, std::function<void(const byte_t*, size_t)> func = nullptr) { return consume(type, 0, func); }
    /**
     * @param   T type [in]
     * @param   binary_t& bin [out]
     */
    return_t consume(T type, binary_t& bin) {
        return_t ret = errorcode_t::success;
        __try2 {
            critical_section_guard guard(_lock);
            auto iter = _map.find(type);
            if (_map.end() == iter) {
                ret = errorcode_t::not_found;
                __leave2;
            } else {
                bin = std::move(iter->second.bin);
                _map.erase(iter);
            }
        }
        __finally2 {}
        return ret;
    }

   protected:
   private:
    struct entry_t {
        t_merge_ovl_intervals<RANGETYPE> part;
        binary_t bin;
    };

    critical_section _lock;
    std::map<T, entry_t> _map;
};

}  // namespace hotplace

#endif
