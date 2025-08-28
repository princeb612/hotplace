/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_BASIC_BINARIES__
#define __HOTPLACE_SDK_BASE_BASIC_BINARIES__

#include <string.h>

#include <functional>
#include <sdk/base/basic/binary.hpp>
#include <sdk/base/nostd/ovl.hpp>

namespace hotplace {

enum binary_flag_t {
    bin_trunc = 1,      // truncate
    bin_wait_fin = 2,   // wait until the fin
    bin_check_fin = 4,  // check fin
};

/**
 * @remarks
 *          t_binaries<tls_secret_t> secrets;
 *          // assign
 *          openssl_digest dgst;
 *          binary_t empty_hash;
 *          dgst.digest(hashalg, empty, empty_hash);
 *          secrets.assign(tls_context_empty_hash, empty_hash);
 *          // get
 *          empty_hash = get_secrets().get(tls_context_empty_hash);
 *          // append
 *          secrets.append(tls_context_fragment, stream + pos, fragment_len);
 *          // erase
 *          secrets.erase(tls_context_fragment);
 */
template <typename T>
class t_binaries {
   public:
    t_binaries() {}

    void assign(T type, const byte_t* stream, size_t size) {
        critical_section_guard guard(_lock);
        auto& entry = _map[type];
        entry.clear();
        if (stream) {
            entry.bin.insert(entry.bin.end(), stream, stream + size);
        }
    }
    void assign(T type, const binary_t& bin) { assign(type, bin.empty() ? nullptr : &bin[0], bin.size()); }
    void append(T type, const byte_t* stream, size_t size) {
        if (stream) {
            critical_section_guard guard(_lock);
            auto& entry = _map[type];
            auto binsize = entry.bin.size();
            entry.bin.insert(entry.bin.end(), stream, stream + size);
        }
    }
    void append(T type, const binary_t& bin) { append(type, bin.empty() ? nullptr : &bin[0], bin.size()); }
    return_t write(T type, size_t offset, const byte_t* stream, size_t size) {
        return_t ret = errorcode_t::success;
        if (stream) {
            critical_section_guard guard(_lock);
            auto& entry = _map[type];
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
    return_t write(T type, size_t offset, const binary_t& bin) { return write(type, offset, bin.empty() ? nullptr : &bin[0], bin.size()); }
    const binary_t& get(T type) { return _map[type].bin; }
    void erase(T type) {
        critical_section_guard guard(_lock);
        auto iter = _map.find(type);
        if (_map.end() != iter) {
            _map.erase(iter);
        }
    }
    void clear() { _map.clear(); }

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
    return_t produce(T type, size_t offset, const binary_t& bin) { return write(type, offset, bin.empty() ? nullptr : &bin[0], bin.size()); }

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
    return_t consume(T type, size_t size) {
        return_t ret = errorcode_t::success;
        __try2 {
            critical_section_guard guard(_lock);
            auto iter = _map.find(type);
            if (_map.end() == iter) {
                ret = errorcode_t::not_found;
                __leave2;
            } else {
                auto& bin = iter->second.bin;
                if (size > bin.size()) {
                    ret = errorcode_t::out_of_range;
                    __leave2;
                } else {
                    bin.erase(bin.begin(), bin.begin() + size);
                }
            }
        }
        __finally2 {}
        return ret;
    }

   protected:
   private:
    struct entry_t {
        binary_t bin;

        void clear() { bin.clear(); }
    };

    critical_section _lock;
    std::map<T, entry_t> _map;
};

}  // namespace hotplace

#endif
