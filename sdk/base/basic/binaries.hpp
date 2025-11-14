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
#include <hotplace/sdk/base/basic/binary.hpp>
#include <hotplace/sdk/base/nostd/ovl.hpp>

namespace hotplace {

enum binary_flag_t {
    bin_trunc = 0x1,        // truncate
    bin_wait_fin = 0x2,     // wait until the fin
    bin_set_fin = 0x4,      // set fin
    bin_keep_entry = 0x80,  //
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
template <typename T, typename TAG = uint8>
class t_binaries {
   public:
    t_binaries() {}

    /**
     * @brief   assign
     * @param   T id [in]
     * @param   const byte_t* stream [in]
     * @param   size_t size [in]
     * @param   uint32 flags [inopt] bin_set_fin
     */
    void assign(T id, const byte_t* stream, size_t size, uint32 flags = 0) {
        if (stream && size) {
            critical_section_guard guard(_lock);
            auto& entry = _map[id];
            entry.clear();
            entry.part.add(0, size);
            entry.bin.insert(entry.bin.end(), stream, stream + size);
            entry.flags |= (flags & bin_set_fin);
            if (bin_set_fin & flags) {
                entry.finsize = entry.bin.size();
            }
        }
    }
    void assign(T id, const binary_t& bin, uint32 flags = 0) { assign(id, bin.empty() ? nullptr : &bin[0], bin.size(), flags); }

    /**
     * @brief   append
     * @param   T id [in]
     * @param   const byte_t* stream [in]
     * @param   size_t size [in]
     * @param   uint32 flags [inopt] bin_set_fin
     */
    void append(T id, const byte_t* stream, size_t size, uint32 flags = 0) {
        if (stream && size) {
            critical_section_guard guard(_lock);
            auto& entry = _map[id];
            auto binsize = entry.bin.size();
            entry.part.add(binsize, binsize + size);
            entry.bin.insert(entry.bin.end(), stream, stream + size);
            entry.flags |= (flags & bin_set_fin);
            if (bin_set_fin & flags) {
                entry.finsize = entry.bin.size();
            }
        }
    }
    void append(T id, const binary_t& bin) { append(id, bin.empty() ? nullptr : &bin[0], bin.size()); }

    /**
     * @brief   write
     * @param   T id [in]
     * @param   size_t offset [in]
     * @param   const byte_t* stream [in]
     * @param   size_t size [in]
     * @param   uint32 flags [inopt] bin_set_fin
     */
    return_t write(T id, size_t offset, const byte_t* stream, size_t size, uint32 flags = 0) {
        return_t ret = errorcode_t::success;
        if (stream && size) {
            critical_section_guard guard(_lock);
            auto& entry = _map[id];
            entry.part.add(offset, offset + size);
            auto binsize = entry.bin.size();
            if (binsize < (offset + size)) {
                entry.bin.resize(offset + size);
            }
            memcpy(&entry.bin[offset], stream, size);
            entry.flags |= (flags & bin_set_fin);
            if (bin_set_fin & flags) {
                entry.finsize = offset + size;
            }
        } else {
            ret = errorcode_t::do_nothing;
        }
        return ret;
    }
    return_t write(T id, size_t offset, const binary_t& bin, uint32 flags = 0) { return write(id, offset, bin.empty() ? nullptr : &bin[0], bin.size(), flags); }

    /**
     * @brief   get
     * @param   T id [in]
     */
    const binary_t& get(T id) { return _map[id].bin; }

    /**
     * @brief   erase
     * @param   T id [in]
     */
    void erase(T id) {
        critical_section_guard guard(_lock);
        auto iter = _map.find(id);
        if (_map.end() != iter) {
            auto& entry = iter->second;
            if (bin_keep_entry & entry.flags) {
                entry.clear();
            } else {
                _map.erase(iter);
            }
        }
    }

    /**
     * @brief   clear
     */
    void clear() { _map.clear(); }

    /**
     * @brief   is fragmented
     * @param   T id [in]
     */
    bool is_fragmented(T id) {
        bool ret = false;
        critical_section_guard guard(_lock);
        auto iter = _map.find(id);
        if (_map.end() != iter) {
            auto& entry = iter->second;
            auto res = entry.part.merge();
            auto parts = res.size();
            if (1 < parts) {
                ret = true;
            } else if (1 == parts) {
                bool check = ((0 == res[0].s) && (entry.bin.size() == res[0].e));
                if (bin_set_fin & entry.flags) {
                    check = (check && (entry.bin.size() == entry.finsize));
                }
                ret = !check;
            }
        }
        return ret;
    }

    /**
     * @brief   produce
     * @param   T id [in]
     * @param   const byte_t* stream [in]
     * @param   size_t size [in]
     * @param   uint32 flags [inopt] bin_trunc, bin_set_fin
     */
    return_t produce(T id, const byte_t* stream, size_t size, uint32 flags = 0) {
        return_t ret = errorcode_t::success;
        if (bin_trunc & flags) {
            ret = assign(id, stream, size, flags);
        } else {
            ret = append(id, stream, size, flags);
        }
        return ret;
    }
    /**
     * @brief   produce
     * @param   T id [in]
     * @param   const binary_t& bin [in]
     * @param   uint32 flags [inopt] bin_trunc, bin_set_fin
     */
    return_t produce(T id, const binary_t& bin, uint32 flags = 0) {
        return_t ret = errorcode_t::success;
        if (bin_trunc & flags) {
            ret = assign(id, bin, flags);
        } else {
            ret = append(id, bin, flags);
        }
        return ret;
    }
    /**
     * @brief   produce
     * @param   T id [in]
     * @param   size_t offset [in]
     * @param   const byte_t* stream [in]
     * @param   size_t size [in]
     * @param   uint32 flags [inopt] bin_trunc, bin_set_fin
     */
    return_t produce(T id, size_t offset, const byte_t* stream, size_t size, uint32 flags = 0) { return write(id, offset, stream, size, flags); }
    /**
     * @brief   produce
     * @param   T id [in]
     * @param   size_t offset [in]
     * @param   const binary_t& bin [in]
     * @param   uint32 flags [inopt] bin_trunc, bin_set_fin
     */
    return_t produce(T id, size_t offset, const binary_t& bin, uint32 flags = 0) {
        return write(id, offset, bin.empty() ? nullptr : &bin[0], bin.size(), flags);
    }

    return_t peek(T id, binary_t& bin) {
        return_t ret = errorcode_t::success;
        __try2 {
            critical_section_guard guard(_lock);
            auto iter = _map.find(id);
            if (_map.end() == iter) {
                ret = errorcode_t::not_found;
                __leave2;
            } else {
                bin = iter->second.bin;
            }
        }
        __finally2 {}
        return ret;
    }

    /**
     * @brief   consume
     * @param   T id [in]
     * @param   binary_t& bin [out]
     */
    return_t consume(T id, binary_t& bin) {
        return_t ret = errorcode_t::success;
        __try2 {
            critical_section_guard guard(_lock);
            auto iter = _map.find(id);
            if (_map.end() == iter) {
                ret = errorcode_t::not_found;
                __leave2;
            } else {
                bin = std::move(iter->second.bin);
                auto& entry = iter->second;
                if (bin_keep_entry & entry.flags) {
                    entry.clear();
                } else {
                    _map.erase(iter);
                }
            }
        }
        __finally2 {}
        return ret;
    }
    /**
     * @brief   consume
     * @param   T id [in]
     * @param   size_t size [in]
     */
    return_t consume(T id, size_t size) {
        return_t ret = errorcode_t::success;
        __try2 {
            critical_section_guard guard(_lock);
            auto iter = _map.find(id);
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
    /**
     * @brief   consume
     * @param   T id [in]
     * @param   std::function<return_t(const binary_t&, size_t&)> func [in]
     * @param   uint32 flags [inopt]
     */
    return_t consume(T id, std::function<return_t(const binary_t&, size_t&)> func, uint32 flags = 0) {
        return_t ret = errorcode_t::success;
        __try2 {
            critical_section_guard guard(_lock);
            auto iter = _map.find(id);
            if (_map.end() == iter) {
                ret = errorcode_t::not_found;
                __leave2;
            } else {
                bool test = is_fragmented(id);
                if (test) {
                    ret = errorcode_t::more_data;
                    __leave2;
                }

                auto& entry = iter->second;

                ret = func(entry.bin, entry.pos);
                if (errorcode_t::success == ret) {
                    test = (entry.bin.size() == entry.pos);
                    if (test) {
                        if (bin_keep_entry & entry.flags) {
                            entry.clear();
                        } else {
                            _map.erase(iter);
                        }
                    }
                }
            }
        }
        __finally2 {}
        return ret;
    }

    /**
     * @brief   reserve
     * @param   T id [in]
     * @param   const TAG& tag [in]
     * @param   uint32 flags [inopt] bin_wait_fin
     */
    bool reserve(T id, const TAG& tag, uint32 flags = 0) {
        bool ret = false;
        critical_section_guard guard(_lock);
        auto iter = _map.find(id);
        if (_map.end() == iter) {
            auto& entry = _map[id];
            entry.tag = tag;
            entry.flags = bin_keep_entry | (flags & bin_wait_fin);
            ret = true;
        }
        return ret;
    }

    /**
     * @brief   exist
     * @param   T id [in]
     */
    bool exist(uint64 id) {
        bool ret = false;
        critical_section_guard guard(_lock);
        auto iter = _map.find(id);
        if (_map.end() != iter) {
            ret = true;
        }
        return ret;
    }

    /**
     * @brief   tag
     * @param   T id [in]
     * @param   const TAG& tag [in]
     */
    return_t set_tag(uint64 id, const TAG& tag) {
        return_t ret = errorcode_t::success;
        critical_section_guard guard(_lock);
        auto iter = _map.find(id);
        if (_map.end() == iter) {
            ret = errorcode_t::not_found;
        } else {
            iter->second.tag = tag;
        }
        return ret;
    }

    /**
     * @brief   tag
     * @param   T id [in]
     * @param   TAG& tag [out]
     */
    return_t get_tag(uint64 id, TAG& tag) {
        return_t ret = errorcode_t::success;
        critical_section_guard guard(_lock);
        auto iter = _map.find(id);
        if (_map.end() == iter) {
            ret = errorcode_t::not_found;
        } else {
            tag = iter->second.tag;
        }
        return ret;
    }

    void for_each(std::function<void(const T&, const binary_t&)> func) {
        if (func) {
            critical_section_guard guard(_lock);
            for (const auto& pair : _map) {
                func(pair.first, pair.second);
            }
        }
    }

   protected:
   private:
    struct entry_t {
        TAG tag;
        uint32 flags;
        size_t finsize;
        size_t pos;
        t_merge_ovl_intervals<size_t> part;
        binary_t bin;

        entry_t() : tag(TAG()), flags(0), finsize(0), pos(0) {}
        void clear() {
            // keep the tag
            flags &= bin_keep_entry;
            finsize = 0;
            pos = 0;
            part.clear();
            bin.clear();
        }
    };

    critical_section _lock;
    std::map<T, entry_t> _map;
};

}  // namespace hotplace

#endif
