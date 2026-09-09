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
            auto iter = _source.find(key);
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
 * @param   const container_t& c
 * @param   typename std::function<void(typename container_t::const_iterator, int)>
 */

template <typename container_t, typename callback_t>
void for_each_const(const container_t& c, callback_t f) {
    if (c.size()) {
        auto iter = c.begin();
        f(iter++, seek_t::seek_begin);
        for (; c.end() != iter; ++iter) {
            f(iter, seek_t::seek_move);
        }
        f(c.end(), seek_t::seek_end);
    }
}

/**
 * @param container_t& c
 * @param typename std::function<void(typename container_t::iterator, int)> f
 */
template <typename container_t, typename callback_t>
void for_each(container_t& c, callback_t f) {
    if (c.size()) {
        auto iter = c.begin();
        f(iter++, seek_t::seek_begin);
        for (; c.end() != iter; ++iter) {
            f(iter, seek_t::seek_move);
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

struct print_style_t {
    std::string prologue;
    std::string delimiter;
    std::string epilogue;
    size_t indent;
    size_t step;

    print_style_t(const std::string& p = "[", const std::string& d = ", ", const std::string& e = "]", size_t i = 0, size_t s = 0)
        : prologue(p), delimiter(d), epilogue(e), indent(i), step(s) {}

    print_style_t(size_t i, size_t s = 0) : prologue("["), delimiter(", "), epilogue("]"), indent(i), step(s) {}

    print_style_t next(size_t default_step = 1) const {
        size_t next_step = (0 == step) ? default_step : step;
        return print_style_t(prologue, delimiter, epilogue, indent + next_step, next_step);
    }

    // forming nested levels with custom brackets/separators
    print_style_t next(const std::string& p, const std::string& d, const std::string& e, size_t default_step = 1) const {
        size_t next_step = (0 == step) ? default_step : step;
        return print_style_t(p, d, e, indent + next_step, next_step);
    }

    size_t get_parent_indent() const { return (indent >= step) ? (indent - step) : 0; }
};

/**
 * @brief   util
 * @sample
 *          // case #1 - print list (default style)
 *          std::list<int> result = {1, 2, 3};
 *          basic_stream bs;
 *          print(result, bs);
 *          std::cout << bs << std::endl; // [1, 2, 3]
 *
 *          // case #2 - print set (default style)
 *          std::set<int> result = {2, 3, 4};
 *          basic_stream bs;
 *          print(result, bs);
 *          std::cout << bs << std::endl; // [2, 3, 4]
 *
 *          // case #3 - print map (default style)
 *          typedef std::unordered_map<BT, trienode*> children_t;
 *          auto handler = [&](typename children_t::const_iterator iter, basic_stream& bs) -> void {
 *              bs.printf("%c, %p", iter->first, iter->second);
 *          };
 *          print_pair(node->children, bs, handler);
 *          _logger->writeln("children : %s", bs.c_str());
 *
 *          // declare style (indentation 2)
 *          print_style_t style(2);
 *
 *          // case #4 - indentation style
 *          std::map<std::pair<int, std::string>, parser_action> action_table;
 *          // insert into action_table and then ...
 *          auto lambda_action = [](typename std::map<std::pair<int, std::string>, parser_action>::const_iterator it, basic_stream& dbs) -> void {
 *              dbs << "(" << it->first.first << ":" << it->first.second << ") -> ";
 *              auto action = it->second.type;
 *              auto target = it->second.target;
 *              if (parser_action_t::shift == action)
 *                  dbs << "shift";
 *              else if (parser_action_t::reduce == action)
 *                  dbs << "reduce";
 *              else if (parser_action_t::accept == action)
 *                  dbs << "accept";
 *              else if (parser_action_t::error == action)
 *                  dbs << "error";
 *              dbs << " target " << target;
 *          };
 *          dbs << "ACTION\n";
 *          print_pair(action_table, dbs, lambda_action, style);
 *
 *          // case #5 - nested indentation
 *          std::vector<std::set<LR0_item>> lr0_states;
 *          // insert into lr0_states and then ...
 *          auto lambda_lr0 = [&style](typename std::vector<std::set<LR0_item>>::const_iterator it, basic_stream& dbs) -> void {
 *              auto lambda = [](typename std::set<LR0_item>::const_iterator it, basic_stream& dbs) -> void {
 *                  const auto& item = *it;
 *                  dbs << "prod_id " << item.prod_id << " dot_pos " << item.dot_pos;
 *              };
 *              print(*it, dbs, lambda, style.next(2));  // nested indent += 2
 *          };
 *          dbs << "LR0 STATE\n";
 *          print(lr0_states, dbs, lambda_lr0, style);
 *
 */
template <typename container_t, typename stream_type>
void print(const container_t& c, stream_type& s, const print_style_t& style = print_style_t()) {
    auto lambda = [&s, &style](typename container_t::const_iterator iter, int where) -> void {
        const char* endl_str = (style.indent > 0) ? "\n" : "";

        switch (where) {
            case seek_t::seek_begin:
                s << style.prologue << endl_str;
                if (style.indent > 0) {
                    s.fill(style.indent, ' ');
                }
                s << *iter;
                break;
            case seek_t::seek_move:
                s << style.delimiter << endl_str;
                if (style.indent > 0) {
                    s.fill(style.indent, ' ');
                }
                s << *iter;
                break;
            case seek_t::seek_end:
                s << endl_str;
                if (style.indent > 0) {
                    auto parent_indent = style.get_parent_indent();
                    if (parent_indent > 0) {
                        s.fill(parent_indent, ' ');
                    }
                }
                s << style.epilogue;
                break;
        }
    };
    for_each_const<container_t>(c, lambda);
}

template <typename container_t, typename stream_type, typename functor_t>
void print(const container_t& c, stream_type& s, functor_t f, const print_style_t& style = print_style_t()) {
    auto lambda = [&s, &f, &style](typename container_t::const_iterator iter, int where) -> void {
        const char* endl_str = (style.indent > 0) ? "\n" : "";

        switch (where) {
            case seek_t::seek_begin:
                s << style.prologue << endl_str;
                if (style.indent > 0) {
                    s.fill(style.indent, ' ');
                }
                s << "{";
                f(iter, s);
                s << "}";
                break;
            case seek_t::seek_move:
                s << style.delimiter << endl_str;
                if (style.indent > 0) {
                    s.fill(style.indent, ' ');
                }
                s << "{";
                f(iter, s);
                s << "}";
                break;
            case seek_t::seek_end:
                s << endl_str;
                if (style.indent > 0) {
                    auto parent_indent = style.get_parent_indent();
                    if (parent_indent > 0) {
                        s.fill(parent_indent, ' ');
                    }
                }
                s << style.epilogue;
                break;
        }
    };
    for_each_const<container_t>(c, lambda);
}

template <typename container_t, typename stream_type>
void print_pair(const container_t& c, stream_type& s, const print_style_t& style = print_style_t()) {
    auto lambda = [&s, &style](typename container_t::const_iterator iter, int where) -> void {
        const char* endl_str = (style.indent > 0) ? "\n" : "";

        switch (where) {
            case seek_t::seek_begin:
                s << style.prologue << endl_str;
                if (style.indent > 0) {
                    s.fill(style.indent, ' ');
                }
                s << "{" << iter->first << "," << iter->second << "}";
                break;
            case seek_t::seek_move:
                s << style.delimiter << endl_str;
                if (style.indent > 0) {
                    s.fill(style.indent, ' ');
                }
                s << "{" << iter->first << "," << iter->second << "}";
                break;
            case seek_t::seek_end:
                s << endl_str;
                if (style.indent > 0) {
                    auto parent_indent = style.get_parent_indent();
                    if (parent_indent > 0) {
                        s.fill(parent_indent, ' ');
                    }
                }
                s << style.epilogue;
                break;
        }
    };
    for_each_const<container_t>(c, lambda);
}

template <typename container_t, typename stream_type, typename functor_t>
void print_pair(const container_t& c, stream_type& s, functor_t f, const print_style_t& style = print_style_t()) {
    auto lambda = [&s, &f, &style](typename container_t::const_iterator iter, int where) -> void {
        const char* endl_str = (style.indent > 0) ? "\n" : "";

        switch (where) {
            case seek_t::seek_begin:
                s << style.prologue << endl_str;
                if (style.indent > 0) {
                    s.fill(style.indent, ' ');
                }
                s << "{";
                f(iter, s);
                s << "}";
                break;
            case seek_t::seek_move:
                s << style.delimiter << endl_str;
                if (style.indent > 0) {
                    s.fill(style.indent, ' ');
                }
                s << "{";
                f(iter, s);
                s << "}";
                break;
            case seek_t::seek_end:
                s << endl_str;
                if (style.indent > 0) {
                    auto parent_indent = style.get_parent_indent();
                    if (parent_indent > 0) {
                        s.fill(parent_indent, ' ');
                    }
                }
                s << style.epilogue;
                break;
        }
    };
    for_each_const<container_t>(c, lambda);
}

}  // namespace hotplace

#endif
