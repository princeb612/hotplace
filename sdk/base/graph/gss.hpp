/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   gss.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2026.10.01   Soo Han and Gemini  study
 *
 * https://en.wikipedia.org/wiki/Graph-structured_stack
 * https://www.geeksforgeeks.org/dsa/clone-directed-acyclic-graph/
 *
 * see also glr_parser
 */

#ifndef __HOTPLACE_SDK_BASE_GRAPH_GSS__
#define __HOTPLACE_SDK_BASE_GRAPH_GSS__

#include <algorithm>
#include <functional>
#include <hotplace/sdk/base/types.hpp>
#include <list>
#include <map>
#include <memory>
#include <queue>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace hotplace {

template <typename STATE, typename VALUE>
class gss_node : public std::enable_shared_from_this<gss_node<STATE, VALUE>> {
   public:
    using ptr = std::shared_ptr<gss_node<STATE, VALUE>>;

    STATE state;
    VALUE value;
    std::vector<ptr> parents;

    gss_node(const STATE& s, const VALUE& v) : state(s), value(v) {}

    void add_parent(ptr parent_node) {
        if (parent_node) {
            parents.push_back(parent_node);
        }
    }

    void traverse(std::function<void(const ptr&)> visitor, std::unordered_set<gss_node*>& visited) {
        if (visited.find(this) != visited.end()) {
            return;
        }
        visited.insert(this);

        visitor(this->shared_from_this());

        for (auto& parent : parents) {
            if (parent) {
                parent->traverse(visitor, visited);
            }
        }
    }

    void retrace(size_t depth, std::vector<ptr>& current_path, std::function<void(const std::vector<ptr>&)> callback, std::unordered_set<gss_node*>& visited) {
        current_path.push_back(this->shared_from_this());

        if (depth == 0) {
            callback(current_path);
            current_path.pop_back();
            return;
        }

        if (visited.find(this) != visited.end() && depth > 1) {
            current_path.pop_back();
            return;
        }
        visited.insert(this);

        for (auto& parent : parents) {
            if (parent) {
                parent->retrace(depth - 1, current_path, callback, visited);
            }
        }

        visited.erase(this);
        current_path.pop_back();
    }
};

template <typename STATE, typename VALUE>
class gss {
   public:
    using node_type = gss_node<STATE, VALUE>;
    using node_ptr = typename node_type::ptr;

   private:
    std::vector<node_ptr> heads;
    std::unordered_multimap<STATE, node_ptr> node_map;

   public:
    gss() = default;

    node_ptr create_node(const STATE& state, const VALUE& value) {
        auto new_node = std::make_shared<node_type>(state, value);
        node_map.emplace(state, new_node);
        return new_node;
    }

    void add_head(node_ptr node) {
        if (node) {
            heads.push_back(node);
        }
    }

    void clear_heads() { heads.clear(); }

    const std::vector<node_ptr>& get_heads() const { return heads; }

    node_ptr push(node_ptr parent, const STATE& state, const VALUE& value) {
        auto new_node = create_node(state, value);

        if (parent) {
            new_node->add_parent(parent);
        }

        add_head(new_node);
        return new_node;
    }

    node_ptr push_root(const STATE& state, const VALUE& value) { return push(nullptr, state, value); }

    void pop(node_ptr target_head, size_t depth, std::function<void(const std::vector<node_ptr>& path)> reducer) { retrace_paths(target_head, depth, reducer); }

    void traverse_from(node_ptr start_node, std::function<void(const node_ptr&)> visitor) {
        if (!start_node) return;

        std::unordered_set<node_type*> visited;
        start_node->traverse(visitor, visited);
    }

    void traverse_all(std::function<void(const node_ptr&)> visitor) {
        std::unordered_set<node_type*> visited;
        for (auto& head : heads) {
            if (head) {
                head->traverse(visitor, visited);
            }
        }
    }

    void traverse_where(std::function<bool(const node_ptr&)> predicate, std::function<void(const node_ptr&)> visitor) {
        node_ptr target_node = nullptr;

        for (auto& head : heads) {
            if (!head) continue;

            std::unordered_set<node_type*> visited;
            head->traverse(
                [&](const node_ptr& node) {
                    if (!target_node && predicate(node)) {
                        target_node = node;
                    }
                },
                visited);

            if (target_node) break;
        }

        if (target_node) {
            traverse_from(target_node, visitor);
        }
    }

    void traverse_by_state(const STATE& state, std::function<void(const node_ptr&)> visitor) {
        auto range = node_map.equal_range(state);
        for (auto it = range.first; it != range.second; ++it) {
            traverse_from(it->second, visitor);
        }
    }

    void retrace_paths(node_ptr start_node, size_t depth, std::function<void(const std::vector<node_ptr>&)> path_handler) {
        if (!start_node) return;

        std::vector<node_ptr> current_path;
        std::unordered_set<node_type*> visited;
        start_node->retrace(depth, current_path, path_handler, visited);
    }
};

}  // namespace hotplace

#endif
