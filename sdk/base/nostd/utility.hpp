/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   utility.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_BASE_NOSTD_UTILITY__
#define __HOTPLACE_SDK_BASE_NOSTD_UTILITY__

#include <hotplace/sdk/base/error.hpp>
#include <hotplace/sdk/base/syntax.hpp>
#include <hotplace/sdk/base/system/error.hpp>
#include <hotplace/sdk/base/types.hpp>
#include <limits>
#include <set>
#include <type_traits>  // use decay_t to remove const, volatile, reference(&)

namespace hotplace {

/**
 * @brief   find_lessthan_or_equal
 */
template <typename T>
void find_lessthan_or_equal(std::set<T>& container, const T& point, T& value) {
    auto iter = std::lower_bound(container.begin(), container.end(), point);
    if ((container.begin() == iter) && (*iter > point)) {
        value = T();
    } else if ((container.end() == iter) || (*iter > point)) {
        value = *(--iter);
    } else {
        value = *iter;
    }
}

/**
 * @brief   util
 */
template <typename K, typename V>
class t_maphint {
   public:
    t_maphint(std::map<K, V>& source) : _source(source) {}

    return_t find(K const& key, V* value) {
        return_t ret = errorcode_t::success;

        if (value) {
            typename std::map<K, V>::iterator iter = _source.find(key);
            if (_source.end() == iter) {
                ret = errorcode_t::not_found;
            } else {
                *value = iter->second;
            }
        } else {
            ret = errorcode_t::invalid_parameter;
        }
        return ret;
    }

   private:
    std::map<K, V>& _source;
};

template <typename K, typename V>
class t_maphint_const {
   public:
    t_maphint_const(std::map<K, V> const& source) : _source(source) {}

    return_t find(K const& key, V* value) {
        return_t ret = errorcode_t::success;

        if (value) {
            typename std::map<K, V>::const_iterator iter = _source.find(key);
            if (_source.end() == iter) {
                ret = errorcode_t::not_found;
            } else {
                *value = iter->second;
            }
        } else {
            ret = errorcode_t::invalid_parameter;
        }
        return ret;
    }

   private:
    std::map<K, V> const& _source;
};

/**
 * @sample
 *          t_sampling_range<int> sample;
 *          sample.sampling(1);   // getmin  1, getmax 1
 *          sample.sampling(-1);  // getmin -1, getmax 1
 *          sample.sampling(2);   // getmin -1, getmax 2
 *          sample.sampling(-2);  // getmin -2, getmax 1
 */
template <typename T>
class t_sampling_range {
   public:
    t_sampling_range() { reset(); }
    t_sampling_range(const t_sampling_range<T>& other) : _min(other._min), _max(other._max), _flag(other._flag) {}

    void sampling(const T& value) {
        if (0 == _flag) {
            _min = value;
            _max = value;
        } else {
            if (value < _min) {
                _min = value;
            }
            if (value > _max) {
                _max = value;
            }
        }
        _flag |= 0x1;
    }

    T getmin() const {
        if (0 == _flag) {
            return T(0);
        } else {
            return _min;
        }
    }
    T getmax() const {
        if (0 == _flag) {
            return T(0);
        } else {
            return _max;
        }
    }

    void reset() {
        _min = T(0);
        _max = T(0);
        _flag = 0;
    }

    t_sampling_range& operator=(const t_sampling_range<T>& other) {
        _min = other._min;
        _max = other._max;
        _flag = other._flag;
        return *this;
    }

   private:
    T _min;
    T _max;
    uint8 _flag;
};

/**
 * @example
 *          // sketch
 *          t_tracker<uint16> tracker;
 *          tracker.add_group(101, 1, 2);
 *          tracker.add_group(102, 1, 3);
 *          tracker.add_group(103, 2, 4);
 *
 *          tracker.visit(1);
 *          tracker.visit(2);
 *
 *          tracker.is_available(1);    // true
 *          tracker.is_available(2);    // true
 *          tracker.is_available(101);  // true
 *          tracker.is_available(102);  // false
 *
 *          tracker.visit(3);
 *
 *          tracker.is_available(3);    // true
 *          tracker.is_available(102);  // true
 */
template <typename T>
class t_tracker {
   public:
    t_tracker() {}

    template <typename... Args>
    void add_group(T parent, Args... children) {
        std::set<T> members = {children...};
        members.erase(parent);

        if (false == members.empty()) {
            _dictionary[parent] = members;

            for (const auto& child : members) {
                _reverse[child].insert(parent);
            }
        }
    }

    void clear_visited() { _available.clear(); }
    void visit(T id) {
        if (0 == _available.count(id)) {
            if (_dictionary.count(id)) {
                const auto& children = _dictionary[id];
                for (const auto& child_id : children) {
                    if (0 == _available.count(child_id)) {
                        return;
                    }
                }
            }
        }

        _available.insert(id);

        auto it = _reverse.find(id);
        if (_reverse.end() != it) {
            for (const T& parent : it->second) {
                _visited[parent].insert(id);

                if (_visited[parent] == _dictionary[parent]) {
                    visit(parent);
                }
            }
        }
    }
    bool is_available(T id) { return _available.count(id) > 0; }
    bool get(T id, std::set<T>& members) {
        bool ret = false;
        members.clear();
        if (is_available(id)) {
            if (_dictionary.count(id)) {
                members = _dictionary[id];
            } else {
                members.insert(id);
            }
        }
        return ret;
    }

   protected:
    std::map<T, std::set<T>> _reverse;     // reverse index
    std::map<T, std::set<T>> _dictionary;  // member
    std::map<T, std::set<T>> _visited;     // visited
    std::set<T> _available;                // available
};

enum seek_t {
    seek_begin = 0,
    seek_move = 1,
    seek_end = 2,
};

/**
 * @remarks
 *          where  0 seek_begin, 1 seek_set, 2 seek_end
 */

template <typename container_t>
void for_each_const(const container_t& c, typename std::function<void(typename container_t::const_iterator, int)> f) {
    if (c.size()) {
        auto iter = c.begin();
        f(iter++, seek_t::seek_begin);
        while (c.end() != iter) {
            f(iter++, seek_t::seek_move);
        }
        f(c.end(), seek_t::seek_end);
    }
}

template <typename container_t>
void for_each(container_t& c, typename std::function<void(typename container_t::iterator, int)> f) {
    if (c.size()) {
        auto iter = c.begin();
        f(iter++, seek_t::seek_begin);
        while (c.end() != iter) {
            f(iter++, seek_t::seek_move);
        }
        f(c.end(), seek_t::seek_end);
    }
}

template <typename container_t, typename usertype>
void for_each_const(const container_t& c, typename std::function<void(typename container_t::const_iterator, int, usertype&)> f, usertype& u) {
    if (c.size()) {
        auto iter = c.begin();
        f(iter++, seek_t::seek_begin, u);
        while (c.end() != iter) {
            f(iter++, seek_t::seek_move, u);
        }
        f(c.end(), seek_t::seek_end, u);
    }
}

template <typename container_t, typename usertype>
void for_each(container_t& c, typename std::function<void(typename container_t::iterator, int, usertype&)> f, usertype& u) {
    if (c.size()) {
        auto iter = c.begin();
        f(iter++, seek_t::seek_begin, u);
        while (c.end() != iter) {
            f(iter++, seek_t::seek_move, u);
        }
        f(c.end(), seek_t::seek_end, u);
    }
}

/**
 * @brief   util
 * @sample
 *          std::list<int> result = {1, 2, 3};
 *          basic_stream bs;
 *          print<std::list<int>, basic_stream>(result, bs);
 *          std::cout << bs << std::endl; // [1, 2, 3]
 *
 *          std::set<int> result = {2, 3, 4};
 *          basic_stream bs;
 *          print<std::set<int>, basic_stream>(result, bs);
 *          std::cout << bs << std::endl; // [2, 3, 4]
 */
template <typename container_t, typename stream_type>
void print(const container_t& c, stream_type& s, const std::string& mark_prologue = "[", const std::string& mark_delimiter = ", ",
           const std::string& mark_epilogue = "]") {
    auto lambda = [&](typename container_t::const_iterator iter, int where) -> void {
        switch (where) {
            case seek_t::seek_begin:
                s << mark_prologue << *iter;
                break;
            case seek_t::seek_move:
                s << mark_delimiter << *iter;
                break;
            case seek_t::seek_end:
                s << mark_epilogue;
                break;
        }
    };
    for_each_const<container_t>(c, lambda);
}

template <typename container_t, typename stream_type>
void print_pair(const container_t& c, stream_type& s, const std::string& mark_prologue = "[", const std::string& mark_delimiter = ", ",
                const std::string& mark_epilogue = "]") {
    auto lambda = [&](typename container_t::const_iterator iter, int where) -> void {
        switch (where) {
            case seek_t::seek_begin:
                s << mark_prologue << "{" << iter->first << "," << iter->second << "}";
                break;
            case seek_t::seek_move:
                s << mark_delimiter << "{" << iter->first << "," << iter->second << "}";
                break;
            case seek_t::seek_end:
                s << mark_epilogue;
                break;
        }
    };
    for_each_const<container_t>(c, lambda);
}

/**
 * @brief   util
 * @sample
 *          typedef std::unordered_map<BT, trienode*> children_t;
 *          auto handler = [&](typename children_t::const_iterator iter, basic_stream& bs) -> void {
 *              bs.printf("%c, %p", iter->first, iter->second);
 *          };
 *          print_pair<children_t, basic_stream>(node->children, bs, handler);
 *          _logger->writeln("children : %s", bs.c_str());
 */
template <typename container_t, typename stream_type>
void print_pair(const container_t& c, stream_type& s, std::function<void(typename container_t::const_iterator, stream_type&)> f, const std::string& mark_prologue = "[",
                const std::string& mark_delimiter = ", ", const std::string& mark_epilogue = "]") {
    auto lambda = [&](typename container_t::const_iterator iter, int where) -> void {
        switch (where) {
            case seek_t::seek_begin:
                s << mark_prologue << "{";
                f(iter, s);
                s << "}";
                break;
            case seek_t::seek_move:
                s << mark_delimiter << "{";
                f(iter, s);
                s << "}";
                break;
            case seek_t::seek_end:
                s << mark_epilogue;
                break;
        }
    };
    for_each_const<container_t>(c, lambda);
}

}  // namespace hotplace

#endif
