/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_TLS_QUICSTREAMS__
#define __HOTPLACE_SDK_NET_TLS_QUICSTREAMS__

#include <string.h>

#include <sdk/base/basic/binaries.hpp>

namespace hotplace {

/**
 * QUIC FRAME STREAM specific implementation
 */
template <typename T, typename TAG>
class t_quic_streams {
   public:
    t_quic_streams() {}

    bool exist(T type) {
        bool ret = false;
        critical_section_guard guard(_lock);
        auto iter = _map.find(type);
        if (_map.end() != iter) {
            ret = true;
        }
        return ret;
    }
    return_t settag(T type, const TAG& tag) {
        return_t ret = errorcode_t::success;
        critical_section_guard guard(_lock);
        auto iter = _map.find(type);
        if (_map.end() == iter) {
            ret = errorcode_t::not_found;
        } else {
            iter->second.tag = tag;
        }
        return ret;
    }
    return_t gettag(T type, TAG& tag) {
        return_t ret = errorcode_t::success;
        critical_section_guard guard(_lock);
        auto iter = _map.find(type);
        if (_map.end() == iter) {
            ret = errorcode_t::not_found;
        } else {
            tag = iter->second.tag;
        }
        return ret;
    }
    void assign(T type, const byte_t* stream, size_t size) {
        critical_section_guard guard(_lock);
        auto& entry = _map[type];
        entry.clear();
        if (stream && size) {
            entry.part.add(0, size);
            entry.bin.insert(entry.bin.end(), stream, stream + size);
        }
    }
    void assign(T type, const binary_t& bin) { assign(type, bin.empty() ? nullptr : &bin[0], bin.size()); }
    void append(T type, const byte_t* stream, size_t size) {
        critical_section_guard guard(_lock);
        auto& entry = _map[type];
        if (stream && size) {
            auto binsize = entry.bin.size();
            entry.part.add(binsize, binsize + size);
            entry.bin.insert(entry.bin.end(), stream, stream + size);
        }
    }
    void append(T type, const binary_t& bin) { append(type, bin.empty() ? nullptr : &bin[0], bin.size()); }
    return_t write(T type, size_t offset, const byte_t* stream, size_t size, uint32 flags = 0) {
        return_t ret = errorcode_t::success;
        critical_section_guard guard(_lock);
        auto& entry = _map[type];
        if (stream && size) {
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
        }
        return ret;
    }
    return_t write(T type, size_t offset, const binary_t& bin, uint32 flags = 0) {
        return write(type, offset, bin.empty() ? nullptr : &bin[0], bin.size(), flags);
    }
    const binary_t& get(T type) { return _map[type].bin; }
    void erase(T type) {
        critical_section_guard guard(_lock);
        auto iter = _map.find(type);
        if (_map.end() != iter) {
            _map.erase(iter);
        }
    }
    void clear() { _map.clear(); }
    bool is_fragmented(T type, uint32 flags = 0) {
        bool ret = false;
        critical_section_guard guard(_lock);
        auto iter = _map.find(type);
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
     */
    return_t consume(T type, std::function<return_t(const binary_t&, size_t&)> func) {
        return_t ret = errorcode_t::success;
        __try2 {
            critical_section_guard guard(_lock);
            if (is_fragmented(type)) {
                __leave2;
            }
            auto iter = _map.find(type);
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
                            entry.bin.clear();
                            entry.pos = 0;
                        }
                    }
                }
            }
        }
        __finally2 {}
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
            tag = TAG();
            flags = 0;
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
