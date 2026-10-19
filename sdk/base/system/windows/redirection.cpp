/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   redirection.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/system/windows/redirection.hpp>

namespace hotplace {

redirection::redirection() : _handle_stdin_read(nullptr), _handle_stdin_write(nullptr), _handle_stdout_read(nullptr), _handle_stdout_write(nullptr) {}

redirection::~redirection() { close(); }

bool redirection::initialize(SECURITY_ATTRIBUTES* sa) {
    BOOL test = FALSE;
    test = CreatePipe(&_handle_stdin_read, &_handle_stdin_write, sa, 0);
    if (false == test) return false;
    test = CreatePipe(&_handle_stdout_read, &_handle_stdout_write, sa, 0);
    if (false == test) {
        close();
        return false;
    }

    SetHandleInformation(_handle_stdin_write, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(_handle_stdout_read, HANDLE_FLAG_INHERIT, 0);
    return true;
}

void redirection::event_spawned() {
    // close parent-side handles that belong to the child
    if (_handle_stdin_read) {
        CloseHandle(_handle_stdin_read);
        _handle_stdin_read = nullptr;
    }
    if (_handle_stdout_write) {
        CloseHandle(_handle_stdout_write);
        _handle_stdout_write = nullptr;
    }
}

size_t redirection::read_stdout(void* buffer, size_t size) {
    if (nullptr == _handle_stdout_read) return 0;
    DWORD bytesRead = 0;
    BOOL test = ReadFile(_handle_stdout_read, buffer, static_cast<DWORD>(size), &bytesRead, nullptr);
    if (test) {
        return static_cast<size_t>(bytesRead);
    }
    return 0;
}

size_t redirection::write_stdin(const void* data, size_t size) {
    if (nullptr == _handle_stdin_write) return 0;
    DWORD bytesWritten = 0;
    BOOL test = WriteFile(_handle_stdin_write, data, static_cast<DWORD>(size), &bytesWritten, nullptr);
    if (test) {
        return static_cast<size_t>(bytesWritten);
    }
    return 0;
}

void redirection::close() {
    if (_handle_stdin_read) {
        CloseHandle(_handle_stdin_read);
        _handle_stdin_read = nullptr;
    }
    if (_handle_stdin_write) {
        CloseHandle(_handle_stdin_write);
        _handle_stdin_write = nullptr;
    }
    if (_handle_stdout_read) {
        CloseHandle(_handle_stdout_read);
        _handle_stdout_read = nullptr;
    }
    if (_handle_stdout_write) {
        CloseHandle(_handle_stdout_write);
        _handle_stdout_write = nullptr;
    }
}

HANDLE redirection::get_stdin_write_handle() const { return _handle_stdin_write; }

HANDLE redirection::get_stdout_read_handle() const { return _handle_stdout_read; }

HANDLE redirection::get_stdin_read_handle() const { return _handle_stdin_read; }

HANDLE redirection::get_stdout_write_handle() const { return _handle_stdout_write; }

}  // namespace hotplace
