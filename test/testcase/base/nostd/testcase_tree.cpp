/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_tree.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/test/testcase/base/sample.hpp>

void test_tree() {
    _test_case.begin("tree");
    // sketch - Abstract Syntax Tree Representation
    //   - SEQUENCE
    //     - builtin type
    //       - name VisibleString
    //     - builtin type
    //       - ok BOOLEAN
    using treenode = t_treenode<std::string>;
    using tree = t_tree<std::string>;
    tree ast;
    ast.add("SEQUENCE", [](treenode* node) -> void {
        (*node).add_child("builtin type", [](treenode* child) -> void { child->add_child("name VisibleString"); }).add_child("builtin type", [](treenode* child) -> void {
            child->add_child("ok BOOLEAN");
        });
    });

    t_tree_visitor<std::string> visitor([&](treenode* node) -> void {
        if (node) {
            _logger->writeln([&](basic_stream& dbs) -> void {
                int depth = node->depth();
                dbs.fill(depth << 1, ' ');
                dbs.printf("- %s", node->_data.c_str());
            });
        }
    });
    visitor.visit(&ast);
    _test_case.assert(true, __FUNCTION__, "tree");
}

void testcase_tree() { test_tree(); }
