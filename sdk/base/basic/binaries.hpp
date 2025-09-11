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
    bin_trunc = 0x1,        // truncate
    bin_wait_fin = 0x2,     // wait until the fin
    bin_check_fin = 0x4,    // check fin
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

    void assign(T id, const byte_t* stream, size_t size) {
        critical_section_guard guard(_lock);
        auto& entry = _map[id];
        entry.clear();
        if (stream && size) {
            entry.part.add(0, size);
            entry.bin.insert(entry.bin.end(), stream, stream + size);
        }
    }
    void assign(T id, const binary_t& bin) { assign(id, bin.empty() ? nullptr : &bin[0], bin.size()); }

    void append(T id, const byte_t* stream, size_t size) {
        if (stream && size) {
            critical_section_guard guard(_lock);
            auto& entry = _map[id];
            auto binsize = entry.bin.size();
            entry.part.add(binsize, binsize + size);
            entry.bin.insert(entry.bin.end(), stream, stream + size);
        }
    }
    void append(T id, const binary_t& bin) { append(id, bin.empty() ? nullptr : &bin[0], bin.size()); }

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
            if (bin_wait_fin & flags) {
                entry.finsize = offset + size;
                entry.flags |= (bin_wait_fin | bin_check_fin);
            }
        } else {
            ret = errorcode_t::do_nothing;
        }
        return ret;
    }
    return_t write(T id, size_t offset, const binary_t& bin, uint32 flags = 0) { return write(id, offset, bin.empty() ? nullptr : &bin[0], bin.size(), flags); }

    const binary_t& get(T id) { return _map[id].bin; }

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

    void clear() { _map.clear(); }

    bool is_fragmented(T id) {
        bool ret = false;
        critical_section_guard guard(_lock);
        auto iter = _map.find(id);
        if (_map.end() != iter) {
            auto& entry = iter->second;
            // size_t entries = entry.part.size();
            auto res = entry.part.merge();
            if (1 < res.size()) {
                ret = true;
            } else if (1 == res.size()) {
                bool check = ((0 == res[0].s) && (entry.bin.size() == res[0].e));

                uint32 mask = bin_wait_fin | bin_check_fin;
                if (mask == (mask & entry.flags)) {
                    check = (check && (entry.bin.size() == entry.finsize));
                }

                ret = !check;
            }
        }
        return ret;
    }

    /**
     * @param   T id [in]
     * @param   const byte_t* stream [in]
     * @param   size_t size [in]
     * @param   uint32 flags [inopt]
     */
    return_t produce(T id, const byte_t* stream, size_t size, uint32 flags = 0) {
        return_t ret = errorcode_t::success;
        if (bin_trunc & flags) {
            assign(id, stream, size);
        } else {
            append(id, stream, size);
        }
        return ret;
    }
    /**
     * @param   T id [in]
     * @param   const binary_t& bin [in]
     * @param   uint32 flags [inopt]
     */
    return_t produce(T id, const binary_t& bin, uint32 flags = 0) {
        return_t ret = errorcode_t::success;
        if (bin_trunc & flags) {
            assign(id, bin);
        } else {
            append(id, bin);
        }
        return ret;
    }
    /**
     * @param   T id [in]
     * @param   size_t offset [in]
     * @param   const byte_t* stream [in]
     * @param   size_t size [in]
     * @param   uint32 flags [inopt]
     */
    return_t produce(T id, size_t offset, const byte_t* stream, size_t size) { return write(id, offset, stream, size); }
    /**
     * @param   T id [in]
     * @param   size_t offset [in]
     * @param   const binary_t& bin [in]
     */
    return_t produce(T id, size_t offset, const binary_t& bin) { return write(id, offset, bin.empty() ? nullptr : &bin[0], bin.size()); }

    /**
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
    return_t consume(T id, std::function<return_t(const binary_t&, size_t&)> func) {
        return_t ret = errorcode_t::success;
        __try2 {
            critical_section_guard guard(_lock);
            if (is_fragmented(id)) {
                __leave2;
            }
            auto iter = _map.find(id);
            if (_map.end() == iter) {
                ret = errorcode_t::not_found;
                __leave2;
            } else {
                auto& entry = iter->second;
                ret = func(entry.bin, entry.pos);
                if (errorcode_t::success == ret) {
                    if (bin_wait_fin & entry.flags) {
                        // keep entry
                        auto binsize = entry.bin.size();
                        if ((binsize == entry.pos) && (binsize == entry.finsize)) {
                            entry.clear();
                        }
                    }
                }
            }
        }
        __finally2 {}
        return ret;
    }

    bool reserve(T id, const TAG& tag) {
        bool ret = false;
        critical_section_guard guard(_lock);
        auto pib = _map.insert({id, entry_t()});
        if (true == pib.second) {
            auto& entry = pib.first->second;
            entry.tag = tag;
            entry.flags = bin_keep_entry;
        }
        return pib.second;
    }

    bool exist(uint64 id) {
        bool ret = false;
        critical_section_guard guard(_lock);
        auto iter = _map.find(id);
        if (_map.end() != iter) {
            ret = true;
        }
        return ret;
    }

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
            // keep the tag, flags
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
