/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_gss.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/test/testcase/base/sample.hpp>

void test_traverse() {
    _test_case.begin("GSS traverse");
    gss<int, std::string> stack;

    /*
     *     n1 ("A1") \
     *   /             -> n3 ("Merge")
     * n0 ("Root")    /
     *   \         n2 ("A2") /
     */
    auto n0 = stack.create_node(0, "Root");
    auto n1 = stack.create_node(1, "A1");
    auto n2 = stack.create_node(2, "A2");
    auto n3 = stack.create_node(3, "Merge");

    n1->add_parent(n0);
    n2->add_parent(n0);
    n3->add_parent(n1);
    n3->add_parent(n2);

    stack.add_head(n3);

    std::unordered_set<std::string> visited_values;
    size_t total_visits = 0;

    // Traverse from head node (n3)
    stack.traverse_all([&](const gss_node<int, std::string>::ptr& node) {
        total_visits++;
        visited_values.insert(node->value);
        _logger->writeln([&node](basic_stream& dbs) -> void {
            dbs << "Visited Node - State: " << node->state << ", Value: " << node->value << ", Parent Count: " << node->parents.size();
        });
    });

    // n3, n1, n2, n0 total 4 unique nodes must be visited exactly once
    _test_case.assert(total_visits == 4, __FUNCTION__, "assert #total_visits");
    _test_case.assert(visited_values.count("Merge") == 1, __FUNCTION__, "assert #count 1");
    _test_case.assert(visited_values.count("A1") == 1, __FUNCTION__, "assert #count 2");
    _test_case.assert(visited_values.count("A2") == 1, __FUNCTION__, "assert #count 3");
    _test_case.assert(visited_values.count("Root") == 1, __FUNCTION__, "assert #count 4");

    // Traverse starting specifically from n3
    _logger->writeln("traverse starting from node_ptr");
    stack.traverse_from(n3, [](const gss_node<int, std::string>::ptr& node) {
        _logger->writeln([&node](basic_stream& dbs) -> void {
            dbs << "Visited Node - State: " << node->state << ", Value: " << node->value << ", Parent Count: " << node->parents.size();
        });
    });
    _test_case.assert(true, __FUNCTION__, "traverse starting from node_ptr");

    _logger->writeln("traverse from predicator");
    stack.traverse_where(
        [](const gss<int, std::string>::node_ptr& node) {
            return node->value == "Merge";  // node->state == 3
        },
        [](const gss<int, std::string>::node_ptr& node) {
            _logger->writeln([&node](basic_stream& dbs) -> void {
                dbs << "Visited Node - State: " << node->state << ", Value: " << node->value << ", Parent Count: " << node->parents.size();
            });
        });
    _test_case.assert(true, __FUNCTION__, "traverse from predicator");

    _logger->writeln("traverse by state");
    stack.traverse_by_state(3, [](const gss<int, std::string>::node_ptr& node) {
        _logger->writeln([&node](basic_stream& dbs) -> void {
            dbs << "Visited Node - State: " << node->state << ", Value: " << node->value << ", Parent Count: " << node->parents.size();
        });
    });
    _test_case.assert(true, __FUNCTION__, "traverse by state");
}

void test_linear_retrace() {
    // Test Case 1: Simple linear stack retrace
    _test_case.begin("GSS retrace");
    gss<int, std::string> stack;

    auto n0 = stack.create_node(0, "Root");
    auto n1 = stack.create_node(1, "A");
    auto n2 = stack.create_node(2, "B");

    n1->add_parent(n0);
    n2->add_parent(n1);

    size_t path_count = 0;
    stack.retrace_paths(n2, 2, [&](const std::vector<gss_node<int, std::string>::ptr>& path) {
        path_count++;
        // Expected path: n2 -> n1 -> n0
        _test_case.assert(path.size() == 3, __FUNCTION__, "assert #1");
        _test_case.assert(path[0]->value == "B", __FUNCTION__, "assert #2");
        _test_case.assert(path[1]->value == "A", __FUNCTION__, "assert #3");
        _test_case.assert(path[2]->value == "Root", __FUNCTION__, "assert #4");
    });

    _test_case.assert(path_count == 1, __FUNCTION__, "linear retrace");
}

void test_fork_and_merge_retrace() {
    // Test Case 2: Branching and merging stack (Ambiguity simulation)
    _test_case.begin("GSS retrace - fork and merge - Ambiguity simulation");
    gss<int, std::string> stack;

    /*
     *     n1 ("A1") \
     *   /             -> n3 ("Merge")
     * n0 ("Root")    /
     *   \         n2 ("A2") /
     */
    auto n0 = stack.create_node(0, "Root");
    auto n1 = stack.create_node(1, "A1");
    auto n2 = stack.create_node(2, "A2");
    auto n3 = stack.create_node(3, "Merge");

    n1->add_parent(n0);
    n2->add_parent(n0);

    // Merge paths at n3
    n3->add_parent(n1);
    n3->add_parent(n2);

    size_t path_count = 0;
    stack.retrace_paths(n3, 2, [&](const std::vector<gss_node<int, std::string>::ptr>& path) {
        path_count++;
        _test_case.assert(path.size() == 3, __FUNCTION__, "assert #1");
        _test_case.assert(path[0]->value == "Merge", __FUNCTION__, "assert #2");
        _test_case.assert(path[2]->value == "Root", __FUNCTION__, "assert #3");
    });

    // Should find 2 distinct paths (Merge->A1->Root, Merge->A2->Root)
    _test_case.assert(path_count == 2, __FUNCTION__, "Fork and Merge Retrace");
}

void testcase_gss() {
    test_traverse();
    test_linear_retrace();
    test_fork_and_merge_retrace();
}
