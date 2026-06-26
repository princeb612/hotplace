/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   set.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_BASE_NOSTD_SET__
#define __HOTPLACE_SDK_BASE_NOSTD_SET__

#include <hotplace/sdk/base/nostd/bit_set.hpp>
#include <hotplace/sdk/base/nostd/point_set.hpp>
#include <hotplace/sdk/base/nostd/range_set.hpp>

namespace hotplace {

enum class set_type_t {
    range = 0,
    point,
    bit,
};

template <typename T = uint64>
class t_set {
   public:
    t_set(set_type_t type, T start, T end) { build(type, start, end); }
    ~t_set() {}

    t_set& insert(T value) override {
        _worker->insert(value);
        return *this;
    }
    t_set& insert_range(T start, T end) override {
        _worker->insert_range(start, end);
        return *this;
    }
    t_set& erase(T value) override {
        _worker->erase(value);
        return *this;
    }
    t_set& erase_range(T start, T end) override {
        _worker->erase_range(start, end);
        return *this;
    }
    bool contains(T value) override { return has(value); }
    t_set& reset() override { clear(); }

   protected:
    void build(set_type_t type, T start, T end) {
        if (set_type_t::range == type) {
            _worker = std::unique_ptr<t_range_set<T>>(new t_range_set);
            insert_range(start, end);
        } else if (set_type_t::point == type) {
            _worker = std::unique_ptr<t_point_set<T>>(new t_point_set);
            insert_range(start, end);
        } else if (set_type_t::bit == type) {
            _worker = std::unique_ptr<t_bit_set<T>>(new t_bit_set(start, end));
        }
    }

   private:
    std::unique_ptr<t_set_t<T>> _worker;
};

}  // namespace hotplace

#endif
