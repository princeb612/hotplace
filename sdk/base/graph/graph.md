## Graph - published by Gemini

---

### 1. Overview and Key Features

* **Module Role**: C++11-based Template Graph Data Structure and Search/Shortest Path Algorithm Library.
* **Key Features**:
  * **Directed/Undirected Graph Support**: Supports `add_directed_edge()`, `add_undirected_edge()`, and `graph_directed`/`graph_undirected` modes.
  * **Various Search and Shortest Path Algorithms Support**: Implements Adjacency List (`graph_adjacent_list`), Depth-First Search (`graph_dfs`), Breadth-First Search (`graph_bfs`), and Dijkstra Shortest Path (`graph_dijkstra`).
  * **Method Chaining**: Designed with Interfaces enabling consecutive calls like `add_edge()` and `add_vertex()`.
  * **Dijkstra Path Reconstruction Support**: Beyond simple distance computation, reconstructs multiple equal-cost shortest paths into a path list via the `filler` recursive function inside `do_infer()`.
* **C++11 Features**:
  * Supports User-defined literals (`operator"" _min`, `operator"" _hour`) for intuitive time/weight representation.
  * Optimizes Vertex/Edge data copy overhead via `std::move`-based Move Constructors and Move Assignment Operators.
  * Utilizes `std::function`-based Visitor Function Interface (`visitor_t`) and Lambda functions.

---

### 2. Core Implementation Areas and Technical Elements

* **Graph Data Structuring**: Abstracts Vertex and Edge with Template Type `T` to support various data types (integers, chars, strings) as Vertex keys.
* **Separation of Graph and Search Algorithms**: Decouples Graph Structure management (`t_graph`) from Algorithm Execution objects (derived classes from `graph_search`) to ensure readability and extensibility.
* **Two-Phase Search Framework**: Encapsulates path reconstruction logic by separating execution into the Search/Learning Phase (`learn()`) and Result Inference/Reconstruction Phase (`infer()`).

---

### 3. Major Data Structures/Classes and API Structure

**Graph Data Management (`hotplace::t_graph<T>`)**

```cpp
namespace hotplace {

template <typename T>
class t_graph {
   public:
    // Add Vertex and Edge (Supports Method Chaining)
    t_graph& add_vertex(const T& d);
    t_graph& add_edge(const T& from, const T& to, int weight = 1, graph_direction_t d = graph_directed);
    t_graph& add_directed_edge(const T& from, const T& to, int weight = 1);
    t_graph& add_undirected_edge(const T& from, const T& to, int weight = 1);

    // Factory Methods for Algorithm Object Creation
    graph_adjacent_list* build_adjacent();
    graph_dfs* build_dfs();
    graph_bfs* build_bfs();
    graph_dijkstra* build_dijkstra();
};

}  // namespace hotplace

```

**Graph Search Base Class (`graph_search`)**
  * `learn()`: Pre-computes and learns search/shortest distance information for each vertex.
  * `infer()`: Constructs the final search path based on learned results.
  * `traverse(...)`: Receives a callback function to traverse and output search results and paths (Path/Distance).

---

### 4. Core Operating Mechanism

* **Internal Vertex and Edge Structures**:
  * `vertex`: Stores internal data `T _data`, overloading `operator<` and `operator==` for `std::set` management.
  * `edge`: Consists of `_from`, `_to`, `_weight`, and `_direction`; automatically registers reverse edge internally when adding undirected edges.
* **Dijkstra Algorithm (`graph_dijkstra`)**:
  * Utilizes `std::priority_queue<std::pair<int, T>, std::vector<...>, std::greater<...>>`.
  * Records shortest distance from start point in `_dist` map, and tracks/stores predecessor vertices forming shortest paths in `_path` map.
  * Executes `filler` lambda function in `do_infer()` to trace backwards and construct complete route (`route_t`) from source to destination.

---

### 5. Usage Example (C++11 Standard)

```cpp
#include <iostream>
#include <string>
#include <list>
#include <functional>
#include <hotplace/sdk/base/nostd/graph.hpp>

// Single Exit Point Macro definition
#define __try2 do {
#define __finally2 } while(0);
#define __leave2 break;

// C++11 User-defined literals for graph weights
int operator"" _min(unsigned long long int x) { return static_cast<int>(x); }
int operator"" _hour(unsigned long long int x) { return static_cast<int>(x * 60); }
int operator"" _hour(long double x) { return static_cast<int>(x * 60); }

int main() {
    int ret = 0;

    __try2
        using namespace hotplace;

        // 1. Integer Vertex Graph (Undirected weighted edges)
        t_graph<int> g1;
        g1.add_undirected_edge(0, 1, 4)
          .add_undirected_edge(0, 7, 8)
          .add_undirected_edge(1, 2, 8)
          .add_undirected_edge(7, 8, 7)
          .add_undirected_edge(2, 8, 2);

        // Build Dijkstra Shortest Path algorithm
        auto shortest = g1.build_dijkstra();
        if (nullptr == shortest) {
            ret = -1;
            __leave2;
        }

        // Two-phase execution: learn -> infer
        shortest->learn().infer();

        // Traverse shortest path from vertex 0 to 8
        shortest->traverse(0, 8, [](const int& from, const int& to, int distance, const std::list<int>& path) {
            std::cout << "Path [" << from << " -> " << to << "] distance: " << distance << "\nNodes: ";
            for (auto node : path) {
                std::cout << node << " ";
            }
            std::cout << "\n";
        });

        delete shortest;

        // 2. String Vertex Graph with User-defined Literals
        t_graph<std::string> g2;
        g2.add_edge("get up", "eat breakfast", 15_min)
          .add_edge("eat breakfast", "go to work", 1_hour)
          .add_edge("go to work", "work", 8_hour)
          .add_edge("work", "go home", 1_hour);

        auto dfs = g2.build_dfs();
        if (dfs) {
            dfs->learn().infer();
            dfs->traverse("get up", [](const std::string& from, const std::string& to, int weight, const std::list<std::string>& path) {
                std::cout << "DFS traversal from " << from << " to " << to << "\n";
            });
            delete dfs;
        }

    __finally2

    return ret;
}

```

---

### 6. TODO list

| ID | Priority | Task Description | Status | Remarks |
| --- | --- | --- | --- | --- |
| ~~TODO-GRAPH-01~~ | `HIGH` | Convert raw pointer return types of `t_graph::build_*` factory methods to `std::unique_ptr` smart pointers to prevent memory leaks | `Open` | Needs conversion to smart pointers |
| ~~TODO-GRAPH-02~~ | `MEDIUM` | Add negative edge weight validation and error handling logic in `graph_dijkstra` implementation | `Open` | Enhance validation logic |
