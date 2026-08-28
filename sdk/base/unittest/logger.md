## `logger` - published by Gemini

### 1. Overview and Architecture

* The `logger` module is a logging system supporting multithreaded environments, built upon the Builder Pattern and thread-local context management.
* It applies a delayed flush mechanism using a background consumer thread to minimize I/O bottlenecks.

#### Key Features

1. **Builder Pattern-Based Object Creation (`logger_builder`)**:
* Uses chaining via `logger_builder` to configure standard output, file storage, flush interval/size, time format, test-case bindings, and build the logger instance.
2. **Thread-Level Data Isolation (`logger_item`)**:
* Maps an independent `basic_stream` buffer per thread ID (`tid`) to minimize synchronization overhead between threads.
* Manages memory lifecycle safely based on reference counting (`t_shared_reference`).
3. **Deferred Flushing & Consumer Thread**:
* A background thread detects buffer size and elapsed time of the file buffer (`delayed`) at regular intervals (`logger_interval`) to perform batch flushes.
4. **ANSI Console Color Support (`console_color`)**:
* Enhances terminal log readability by allowing specification of style, foreground color, and background color.
5. **Memory Dump Functions (`dump`, `hdump`)**:
* Serializes binary data and memory addresses into hexadecimal (Hex) dump formats for output.

---

### 2. Core Classes and API Reference

#### Key Components

* **`logger_builder`**: Combines main configuration parameters of the logger (console, file, flush conditions, etc.), outputs ASCII art banners, and creates `logger` instances.
* **`logger_item`**: A structure allocated per thread holding a real-time output buffer (`bs`), a delayed buffer for file flushing (`delayed`), timestamps, and reference counts.
* **`logger`**: Provides core interfaces such as thread-safe logging, log level filtering, memory dumps, and ANSI color outputs.

#### Key Methods

| Class / Method | Description |
| --- | --- |
| **`logger_builder::set_logfile`** | Enables file logging and specifies the output log file path. |
| **`logger::writeln` / `write**` | Writes format strings (`vprintf`), `std::string`, `basic_stream`, `stream_t*`, or lambda function data to output buffers. |
| **`logger::consoleln`** | Performs console-exclusive output. |
| **`logger::dump` / `hdump**` | Writes memory addresses and binary data in Hex dump format to the output buffer (headers supported). |
| **`logger::flush`** | Checks logs accumulated in the delayed buffer (`delayed`) and writes them to the file in a single operation. |
| **`logger::setcolor` / `colorln**` | Sets console styles and colors to produce colored log output. |

---

### 3. Core Internal Architecture

#### 3.1. Thread-Local Context Flow

Isolates buffers based on thread IDs upon log requests to minimize contention during concurrent writes:

```
[Thread A] ──► get_context() ──► Lookup TID A ──► logger_item A (bs / delayed)
                                                         │
                                                         ▼
                                             Write basic_stream data
                                                         │
                                                         ▼
                                       Call touch() -> Transfer to delayed buffer

```

#### 3.2. Async Flushing Pipeline

The background thread `consumer` executes periodically and invokes `flush(true)`:

```
[Consumer Thread]
      │
      ▼ (Waits per interval)
  flush(check = true)
      │
      ├─► Condition Check: (Current Time - timestamp >= flush_time) OR (bs.size() >= flush_size)
      │
      └─► When met: Batch write to file via std::ofstream (ios::app) -> bs.clear()

```

---

### 4. C++11 Usage Example

```cpp
#include <iostream>
#include <hotplace/sdk/base/unittest/logger.hpp>

void run_logger_sample() {
    using namespace hotplace;

    // -------------------------------------------------------------
    // Demo 1: Build Logger Instance
    // -------------------------------------------------------------
    logger_builder builder;
    builder.set(logger_t::logger_stdout, 1)
           .set(logger_t::logger_interval, 200)
           .set(logger_t::logger_flush_time, 5)
           .set_timeformat("Y-M-D h:m:s.f ")
           .set_logfile("sample.log");

    // Create shared logger instance
    t_shared_instance<logger> log_inst;
    log_inst.make_share(builder.build());

    // -------------------------------------------------------------
    // Demo 2: Basic Writing & Level Filtering
    // -------------------------------------------------------------
    log_inst->set_loglevel(loglevel_t::loglevel_trace);
    log_inst->writeln("Basic log message with format: %d", 1234);
    log_inst->writeln(loglevel_t::loglevel_debug, "Debug message level check");

    // -------------------------------------------------------------
    // Demo 3: Console Color Logging
    // -------------------------------------------------------------
    log_inst->setcolor(console_style_t::bold, console_color_t::fgcyan, console_color_t::black);
    log_inst->colorln("Colored log output via logger");

    // -------------------------------------------------------------
    // Demo 4: Hex Memory Dump
    // -------------------------------------------------------------
    uint8_t buffer[16] = {0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21, 0x00, 0x0A, 0x0D, 0xFF};
    log_inst->hdump("Memory Dump Header", buffer, sizeof(buffer));

    // Force flush
    log_inst->flush();
}

int main() {
    run_logger_sample();
    return 0;
}

```

---

### 5. TODO List Tracker

| ID | Priority | Task Description | Status | Remarks |
| --- | --- | --- | --- | --- |
| **TODO-LOG-01** | `HIGH` | **Implement log file rotation (`logger_rotate_size`, `logger_max_file`)**<br><br>- Add logic to split files when size limits are exceeded and maintain maximum file counts | `To Do` | `logger.cpp` (Extend `flush`) |
| **TODO-LOG-02** | `MEDIUM` | **Build thread context (`_logger_stream_map`) cleanup mechanism for exited threads**<br><br>- Implement garbage collection logic to prevent resource leaks upon thread termination | `To Do` | `logger.cpp`<br> |
