/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   tree.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_BASE_NOSTD_TREE__
#define __HOTPLACE_SDK_BASE_NOSTD_TREE__

#include <hotplace/sdk/base/basic/types.hpp>
#include <hotplace/sdk/base/system/shared_instance.hpp>

namespace hotplace {

// clang-format off
template <typename TYPE> struct t_treenode;
template <typename TYPE> class t_tree_visitor;
template <typename TYPE> class t_tree;
// clang-format on

/**
 * AST (Abstract Syntax Tree), DFS (Depth-First Search)
 */
template <typename TYPE>
struct t_treenode {
    TYPE _data;
    t_treenode* _parent;
    std::list<t_treenode*> _children;

    t_treenode(const TYPE& data) : _data(data), _parent(nullptr) {}
    t_treenode(const t_treenode& other) : _parent(nullptr) { *this = other; }
    ~t_treenode() { clear(); }

    t_treenode& operator=(const t_treenode& other) {
        if (this == &other) return *this;

        clear();
        _data = other._data;

        for (const auto& child : other._children) {
            auto node = child->clone();
            node->_parent = this;
            _children.push_back(node);
        }
        return *this;
    }

    t_treenode* clone() { return new t_treenode(*this); }

    void clear() {
        while (false == _children.empty()) {
            auto* child = _children.front();
            _children.pop_front();
            delete child;
        }
    }

    static t_treenode<TYPE>* add(const TYPE& data, t_treenode<TYPE>* parent) {
        auto node = new t_treenode<TYPE>(data);
        if (parent) {
            parent->_children.push_back(node);
            node->_parent = parent;
        }
        return node;
    }

    t_treenode<TYPE>& add_child(const TYPE& data) {
        add(data, this);
        return *this;
    }

    t_treenode<TYPE>& add_child(const TYPE& data, std::function<void(t_treenode<TYPE>*)> func) {
        auto node = add(data, this);
        if (func) func(node);
        return *this;
    }

    void accept(t_tree_visitor<TYPE>* visitor) {
        visitor->describe(this);
        for (const auto& child : _children) {
            child->accept(visitor);
        }
    }

    int depth() const {
        int depth = 0;
        const auto* temp = _parent;
        while (temp && temp->_parent) {
            ++depth;
            temp = temp->_parent;
        }
        return depth;
    }

    void for_each(std::function<void(t_treenode<TYPE>*)> f) const {
        for (const auto& child : _children) {
            f(child);
        }
    }

    TYPE& get() { return _data; }
    const TYPE& get() const { return _data; }
    bool is_root() { return nullptr == _parent; }
    bool is_leaf() { return _children.empty(); }
    bool is_branch() { return (false == _children.empty()); }
    size_t size() { return _children.size(); }
    t_treenode<TYPE>* parent() const { return _parent; }
};

template <typename TYPE>
class t_tree_visitor {
   public:
    using treenode = t_treenode<TYPE>;
    using nodepath = std::vector<treenode*>;
    t_tree_visitor(std::function<void(t_treenode<TYPE>*)> func) : _descriptor(func) {}

    void visit(t_tree<TYPE>* tree) {
        if (tree) tree->accept(this);
    };
    void describe(treenode* node) {
        if (_descriptor) _descriptor(node);
    }

   private:
    std::function<void(treenode*)> _descriptor;
};

/**
 * @brief   tree
 * @example
 *          // sketch
 *          - SEQUENCE
 *            - builtin type
 *              - name VisibleString
 *            - builtin type
 *              - ok BOOLEAN
 *
 *          using treenode = t_treenode<std::string>;
 *          using tree = t_tree<std::string>;
 *
 *          tree ast;
 *          ast.add("SEQUENCE", [](treenode* node) -> void {
 *              (*node)
 *                  .add_child("builtin type", [](treenode* child) -> void { child->add_child("name VisibleString"); })
 *                  .add_child("builtin type", [](treenode* child) -> void { child->add_child("ok BOOLEAN"); });
 *          });
 *
 *          t_tree_visitor<std::string> visitor([&](treenode* node) -> void {
 *              if (node) {
 *                  _logger->writeln([&](basic_stream& dbs) -> void {
 *                      int depth = node->depth();
 *                      dbs.fill(depth << 1, ' ');
 *                      dbs.printf("- %s", node->_data.c_str());
 *                  });
 *              }
 *          });
 *          visitor.visit(&ast);
 */
template <typename TYPE>
class t_tree {
   public:
    t_tree() : _root(t_treenode<TYPE>::add(TYPE(), nullptr)), _size(0) { _shared.make_share(this); }
    ~t_tree() { delete _root; }

    t_treenode<TYPE>* root() const { return _root; }

    t_treenode<TYPE>* add_node(const TYPE& data, t_treenode<TYPE>* parent) {
        auto node = t_treenode<TYPE>::add(data, parent ? parent : _root);
        ++_size;
        return node;
    }

    t_tree<TYPE>& add(const TYPE& data, std::function<void(t_treenode<TYPE>*)> func) {
        auto node = add_node(data, _root);
        func(node);
        return *this;
    }
    t_tree<TYPE>& add(const TYPE& data, t_treenode<TYPE>* parent, std::function<void(t_treenode<TYPE>*)> func) {
        auto node = add_node(data, parent ? parent : _root);
        func(node);
        return *this;
    }

    void clear() {
        _root->clear();
        _size = 0;
    }

    void accept(t_tree_visitor<TYPE>* visitor) {
        for (auto& child : _root->_children) {
            child->accept(visitor);
        }
    }

    size_t size() { return _size; }
    bool empty() { return 0 == _size; }

    void addref() { _shared.addref(); }
    void release() { _shared.delref(); }

   protected:
   private:
    t_treenode<TYPE>* _root;
    size_t _size;
    t_shared_reference<t_tree<TYPE>> _shared;
};

}  // namespace hotplace

#endif
