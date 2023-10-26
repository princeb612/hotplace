/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <iostream>
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/system/trace.hpp>
#include <sdk/base/system/windows/debug_trace.hpp>

namespace hotplace {

return_t trace(return_t errorcode) {
    return_t ret = errorcode_t::success;

    if (errorcode_t::success != errorcode) {
        uint32 option = get_trace_option();
        if (trace_option_t::trace_bt & option) {
            debug_trace_context_t* handle = nullptr;
            basic_stream stream;

            // PDB
            CONTEXT rtlcontext;
            debug_trace dbg;
            dbg.open(&handle);
            dbg.capture(&rtlcontext);
            ret = dbg.trace(handle, &rtlcontext, &stream);
            dbg.close(handle);

            std::cout << stream.c_str() << std::endl;
        }
    }
    return ret;
}

#define BACKTRACE_CONTEXT_SIGNATURE 0x20101221

typedef struct _backtrace_context_t : debug_trace_context_t {
    uint32 signature;
    HMODULE imagehlp_handle;
    struct _mssdk {
#if defined __x86_64__
        STACKWALK64 lpfnStackWalk;
        SYMFUNCTIONTABLEACCESS64 lpfnSymFunctionTableAccess;
        SYMGETLINEFROMADDR64 lpfnSymGetLineFromAddr;
        SYMLOADMODULE64 lpfnSymLoadModule;
        SYMGETMODULEBASE64 lpfnSymGetModuleBase;
        SYMGETMODULEINFO64 lpfnSymGetModuleInfo;
        SYMGETSYMFROMADDR64 lpfnSymGetSymFromAddr;
#else
        STACKWALK lpfnStackWalk;
        SYMFUNCTIONTABLEACCESS lpfnSymFunctionTableAccess;
        SYMGETLINEFROMADDR lpfnSymGetLineFromAddr;
        SYMLOADMODULE lpfnSymLoadModule;
        SYMGETMODULEBASE lpfnSymGetModuleBase;
        SYMGETMODULEINFO lpfnSymGetModuleInfo;
        SYMGETSYMFROMADDR lpfnSymGetSymFromAddr;
#endif
        SYMCLEANUP lpfnSymCleanup;
        SYMGETOPTIONS lpfnSymGetOptions;
        SYMINITIALIZE lpfnSymInitialize;
        SYMSETOPTIONS lpfnSymSetOptions;
        UNDECORATESYMBOLNAME lpfnUnDecorateSymbolName;
    } mssdk;

    _backtrace_context_t() {
        signature = BACKTRACE_CONTEXT_SIGNATURE;
        imagehlp_handle = nullptr;
        memset(&mssdk, 0, sizeof(struct _mssdk));
    }
} backtrace_context_t;

debug_trace::debug_trace() {
    // do nothing
}

debug_trace::~debug_trace() {
    // do nothing
}

return_t enum_modules_handler(uint32 type, uint32 count, void* data[], CALLBACK_CONTROL* control, void* parameter) {
    return_t ret = errorcode_t::success;
    backtrace_context_t* context = (backtrace_context_t*)parameter;
    HANDLE process_handle = GetCurrentProcess();

    switch (type) {
        case enum_modules_t::enum_toolhelp: {
            MODULEENTRY32* entry = (MODULEENTRY32*)data[0];
            context->mssdk.lpfnSymLoadModule(process_handle, 0, entry->szExePath, entry->szModule, (arch_t)entry->modBaseAddr, entry->modBaseSize);
        } break;
        case enum_modules_t::enum_psapi: {
            HMODULE module_handle = (HMODULE)data[0];
            MODULEINFO* module_info = (MODULEINFO*)data[1];
            HMODULE psapi_handle = nullptr;
            DECLARE_DLLNAME_PSAPI;
            __try2 {
                ret = get_module_handle(&psapi_handle, DLLNAME_PSAPI, loadlibrary_path_t::system_path, nullptr);
                if (errorcode_t::success != ret) {
                    ret = get_module_handle(&psapi_handle, DLLNAME_PSAPI, loadlibrary_path_t::current_path, nullptr);
                }
                if (errorcode_t::success != ret) {
                    __leave2;
                }

                DECLARE_NAMEOF_API_GETMODULEFILENAMEEX;
                DECLARE_NAMEOF_API_GETMODULEBASENAME;

                GETMODULEFILENAMEEX lpfnGetModuleFileNameEx = nullptr;
                GETMODULEBASENAME lpfnGetModuleBaseName = nullptr;

                GETPROCADDRESS(GETMODULEFILENAMEEX, lpfnGetModuleFileNameEx, psapi_handle, NAMEOF_API_GETMODULEFILENAMEEX, ret, __leave2);
                GETPROCADDRESS(GETMODULEBASENAME, lpfnGetModuleBaseName, psapi_handle, NAMEOF_API_GETMODULEBASENAME, ret, __leave2);

                TCHAR buffer_image[1 << 10];
                lpfnGetModuleFileNameEx(process_handle, module_handle, buffer_image, RTL_NUMBER_OF(buffer_image));
                TCHAR buffer_module[1 << 8];
                lpfnGetModuleBaseName(process_handle, module_handle, buffer_module, RTL_NUMBER_OF(buffer_module));

                context->mssdk.lpfnSymLoadModule(process_handle, 0, buffer_image, buffer_module, (arch_t)module_info->lpBaseOfDll, module_info->SizeOfImage);
            }
            __finally2 {
                // do nothing
            }
        } break;
    }

    return ret;
}

return_t debug_trace::open(debug_trace_context_t** handle) {
    return_t ret = errorcode_t::success;
    backtrace_context_t* context = nullptr;
    HMODULE imagehlp_handle = nullptr;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        DECLARE_DLLNAME_IMAGEHLP;
        ret = load_library(&imagehlp_handle, DLLNAME_IMAGEHLP, loadlibrary_path_t::system_path, nullptr);

        __try_new_catch(context, new backtrace_context_t, ret, __leave2);

#ifdef __x86_64__
        DECLARE_NAMEOF_API_STACKWALK64;
        DECLARE_NAMEOF_API_SYMFUNCTIONTABLEACCESS64;
        DECLARE_NAMEOF_API_SYMGETLINEFROMADDR64;
        DECLARE_NAMEOF_API_SYMGETMODULEBASE64;
        DECLARE_NAMEOF_API_SYMGETMODULEINFO64;
        DECLARE_NAMEOF_API_SYMGETSYMFROMADDR64;
        DECLARE_NAMEOF_API_SYMLOADMODULE64;

        GETPROCADDRESS(STACKWALK64, context->mssdk.lpfnStackWalk, imagehlp_handle, NAMEOF_API_STACKWALK64, ret, __leave2);
        GETPROCADDRESS(SYMFUNCTIONTABLEACCESS64, context->mssdk.lpfnSymFunctionTableAccess, imagehlp_handle, NAMEOF_API_SYMFUNCTIONTABLEACCESS64, ret,
                       __leave2);
        GETPROCADDRESS(SYMGETLINEFROMADDR64, context->mssdk.lpfnSymGetLineFromAddr, imagehlp_handle, NAMEOF_API_SYMGETLINEFROMADDR64, ret, __leave2);
        GETPROCADDRESS(SYMLOADMODULE64, context->mssdk.lpfnSymLoadModule, imagehlp_handle, NAMEOF_API_SYMLOADMODULE64, ret, __leave2);
        GETPROCADDRESS(SYMGETMODULEBASE64, context->mssdk.lpfnSymGetModuleBase, imagehlp_handle, NAMEOF_API_SYMGETMODULEBASE64, ret, __leave2);
        GETPROCADDRESS(SYMGETMODULEINFO64, context->mssdk.lpfnSymGetModuleInfo, imagehlp_handle, NAMEOF_API_SYMGETMODULEINFO64, ret, __leave2);
        GETPROCADDRESS(SYMGETSYMFROMADDR64, context->mssdk.lpfnSymGetSymFromAddr, imagehlp_handle, NAMEOF_API_SYMGETSYMFROMADDR64, ret, __leave2);
#else
        DECLARE_NAMEOF_API_STACKWALK;
        DECLARE_NAMEOF_API_SYMFUNCTIONTABLEACCESS;
        DECLARE_NAMEOF_API_SYMGETLINEFROMADDR;
        DECLARE_NAMEOF_API_SYMGETMODULEBASE;
        DECLARE_NAMEOF_API_SYMGETMODULEINFO;
        DECLARE_NAMEOF_API_SYMGETSYMFROMADDR;
        DECLARE_NAMEOF_API_SYMLOADMODULE;

        GETPROCADDRESS(STACKWALK, context->mssdk.lpfnStackWalk, imagehlp_handle, NAMEOF_API_STACKWALK, ret, __leave2);
        GETPROCADDRESS(SYMFUNCTIONTABLEACCESS, context->mssdk.lpfnSymFunctionTableAccess, imagehlp_handle, NAMEOF_API_SYMFUNCTIONTABLEACCESS, ret, __leave2);
        GETPROCADDRESS(SYMGETLINEFROMADDR, context->mssdk.lpfnSymGetLineFromAddr, imagehlp_handle, NAMEOF_API_SYMGETLINEFROMADDR, ret, __leave2);
        GETPROCADDRESS(SYMLOADMODULE, context->mssdk.lpfnSymLoadModule, imagehlp_handle, NAMEOF_API_SYMLOADMODULE, ret, __leave2);
        GETPROCADDRESS(SYMGETMODULEBASE, context->mssdk.lpfnSymGetModuleBase, imagehlp_handle, NAMEOF_API_SYMGETMODULEBASE, ret, __leave2);
        GETPROCADDRESS(SYMGETMODULEINFO, context->mssdk.lpfnSymGetModuleInfo, imagehlp_handle, NAMEOF_API_SYMGETMODULEINFO, ret, __leave2);
        GETPROCADDRESS(SYMGETSYMFROMADDR, context->mssdk.lpfnSymGetSymFromAddr, imagehlp_handle, NAMEOF_API_SYMGETSYMFROMADDR, ret, __leave2);
#endif
        DECLARE_NAMEOF_API_SYMCLEANUP;
        DECLARE_NAMEOF_API_SYMGETOPTIONS;
        DECLARE_NAMEOF_API_SYMINITIALIZE;
        DECLARE_NAMEOF_API_SYMSETOPTIONS;
        DECLARE_NAMEOF_API_UNDECORATESYMBOLNAME;

        GETPROCADDRESS(SYMCLEANUP, context->mssdk.lpfnSymCleanup, imagehlp_handle, NAMEOF_API_SYMCLEANUP, ret, __leave2);
        GETPROCADDRESS(SYMGETOPTIONS, context->mssdk.lpfnSymGetOptions, imagehlp_handle, NAMEOF_API_SYMGETOPTIONS, ret, __leave2);
        GETPROCADDRESS(SYMINITIALIZE, context->mssdk.lpfnSymInitialize, imagehlp_handle, NAMEOF_API_SYMINITIALIZE, ret, __leave2);
        GETPROCADDRESS(SYMSETOPTIONS, context->mssdk.lpfnSymSetOptions, imagehlp_handle, NAMEOF_API_SYMSETOPTIONS, ret, __leave2);
        GETPROCADDRESS(UNDECORATESYMBOLNAME, context->mssdk.lpfnUnDecorateSymbolName, imagehlp_handle, NAMEOF_API_UNDECORATESYMBOLNAME, ret, __leave2);

        DWORD test = 0;
        TCHAR buffer_data[1 << 12];
        size_t buffer_data_size = RTL_NUMBER_OF(buffer_data);
        std::string symbol_search_path;

        test = GetCurrentDirectory(buffer_data_size, buffer_data);
        if (test) {
            symbol_search_path += buffer_data;
            symbol_search_path += ";";
        }

        constexpr char constexpr_symbolpath[] = "NT_SYMBOL_PATH";
        test = GetEnvironmentVariable(constexpr_symbolpath, buffer_data, buffer_data_size);
        if (test) {
            symbol_search_path += buffer_data;
            symbol_search_path += ";";
        }

        constexpr char constexpr_alt_symbolpath[] = "_NT_ALTERNATE_SYMBOL_PATH";
        test = GetEnvironmentVariable(constexpr_alt_symbolpath, buffer_data, buffer_data_size);
        if (test) {
            symbol_search_path += buffer_data;
            symbol_search_path += ";";
        }

        BOOL bret = TRUE;
        bret = context->mssdk.lpfnSymInitialize(GetCurrentProcess(), symbol_search_path.c_str(), TRUE);
        if (FALSE == bret) {
            ret = GetLastError();
            __leave2;
        }

        DWORD options = context->mssdk.lpfnSymGetOptions();
        options |= SYMOPT_LOAD_LINES;
        options &= ~SYMOPT_UNDNAME;
        context->mssdk.lpfnSymSetOptions(options);

        enum_modules(GetCurrentProcess(), enum_modules_handler, context);

        context->imagehlp_handle = imagehlp_handle;
        *handle = context;
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            if (context) {
                delete context;
            }
        }
    }

    return ret;
}

return_t debug_trace::close(debug_trace_context_t* handle) {
    return_t ret = errorcode_t::success;
    backtrace_context_t* context = (backtrace_context_t*)handle;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        context->mssdk.lpfnSymCleanup(GetCurrentProcess());

        if (context->imagehlp_handle) {
            FreeLibrary(context->imagehlp_handle);
        }

        delete context;
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t debug_trace::capture(CONTEXT* rtlcontext) {
    return_t ret = errorcode_t::success;

    /* RtlCaptureContext */
    HMODULE kernel32_handle = nullptr;
    RTLCAPTURECONTEXT lpfnRtlCaptureContext = nullptr;

    __try2 {
        if (nullptr == rtlcontext) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        DECLARE_DLLNAME_KERNEL32;
        ret = get_module_handle(&kernel32_handle, DLLNAME_KERNEL32, loadlibrary_path_t::system_path, nullptr);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        DECLARE_NAMEOF_API_RTLCAPTURECONTEXT;
        GETPROCADDRESS(RTLCAPTURECONTEXT, lpfnRtlCaptureContext, kernel32_handle, NAMEOF_API_RTLCAPTURECONTEXT, ret, __leave2);

        if (lpfnRtlCaptureContext) {
            lpfnRtlCaptureContext(rtlcontext);
        }
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t debug_trace::trace(debug_trace_context_t* handle, CONTEXT* rtlcontext, stream_t* stream) {
    return_t ret = errorcode_t::success;
    backtrace_context_t* context = (backtrace_context_t*)handle;
    BOOL bRet = TRUE;
    HANDLE process_handle = GetCurrentProcess();
    HANDLE thread_handle = GetCurrentThread();
    IMAGEHLP_SYMBOL* symbol = nullptr;

    __try2 {
        if (nullptr == rtlcontext || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (BACKTRACE_CONTEXT_SIGNATURE != context->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        CHAR buffer_undecorated_name[(1 << 10)];
        CHAR buffer_undecorated_fullname[(1 << 10)];

        STACKFRAME frame;
        memset(&frame, 0, sizeof(STACKFRAME));
#if defined __x86_64__
        frame.AddrPC.Offset = rtlcontext->Rip;
        frame.AddrFrame.Offset = rtlcontext->Rbp;
#else
        frame.AddrPC.Offset = rtlcontext->Eip;
        frame.AddrFrame.Offset = rtlcontext->Ebp;
#endif
        frame.AddrPC.Mode = AddrModeFlat;
        frame.AddrFrame.Mode = AddrModeFlat;

        IMAGEHLP_LINE Line;
        memset(&Line, 0, sizeof(IMAGEHLP_LINE));
        Line.SizeOfStruct = sizeof(IMAGEHLP_LINE);

        IMAGEHLP_MODULE Module;
        memset(&Module, 0, sizeof(IMAGEHLP_MODULE));
        Module.SizeOfStruct = sizeof(IMAGEHLP_MODULE);

        DWORD image_type = 0;
#if defined __x86_64__
        image_type = IMAGE_FILE_MACHINE_AMD64;
#else
        image_type = IMAGE_FILE_MACHINE_I386;
#endif
        int nFrameNum = 0;
        DWORD dwOffsetFromSymbol = 0;
        symbol = static_cast<IMAGEHLP_SYMBOL*>(malloc((sizeof(IMAGEHLP_SYMBOL)) + (1 << 10)));
        if (nullptr == symbol) {
            ret = ERROR_OUTOFMEMORY;
            __leave2;
        }

        constexpr char constexpr_debug[] = "debug";
        constexpr char constexpr_frameinfo[] = "#%-4d %08x %08x %08x %08x %08x %08x ";
        constexpr char constexpr_moduleinfo[] = "%s(0x%08x)+0x%08x ";
        constexpr char constexpr_undeco[] = "%s!%s";
        constexpr char constexpr_fileline[] = "+0x%x";
        constexpr char constexpr_line[] = " [%s @ %lu]";

        stream->printf("%s\n", constexpr_debug);

        memset(symbol, 0, (sizeof(IMAGEHLP_SYMBOL)) + (1 << 10));
        symbol->SizeOfStruct = sizeof(IMAGEHLP_SYMBOL);
        symbol->MaxNameLength = (1 << 10);

        typedef std::map<UINT_PTR, IMAGEHLP_MODULE> IMAGEHLP_MODULE_LIST; /* both DWORD and DWORD64 */
        IMAGEHLP_MODULE_LIST modulelist;

        for (nFrameNum = 0;; ++nFrameNum) {
            bRet = context->mssdk.lpfnStackWalk(image_type, process_handle, thread_handle, &frame, rtlcontext, nullptr,
                                                context->mssdk.lpfnSymFunctionTableAccess, context->mssdk.lpfnSymGetModuleBase, nullptr);
            if (FALSE == bRet) {
                break;
            }

            stream->printf(constexpr_frameinfo, nFrameNum, frame.AddrFrame.Offset, frame.AddrReturn.Offset, frame.Params[0], frame.Params[1], frame.Params[2],
                           frame.Params[3]);
            if (0 == frame.AddrPC.Offset) {
                // do nothing
            } else {
                BOOL bModuleInfoRet = context->mssdk.lpfnSymGetModuleInfo(process_handle, frame.AddrPC.Offset, &Module);
                if (TRUE == bModuleInfoRet) {
                    modulelist.insert(std::make_pair(Module.BaseOfImage, Module));
                    stream->printf(constexpr_moduleinfo, base_name(Module.ImageName).c_str(), Module.BaseOfImage, frame.AddrPC.Offset - Module.BaseOfImage);
                }

                bRet = context->mssdk.lpfnSymGetSymFromAddr(process_handle, frame.AddrPC.Offset, (arch_t*)&dwOffsetFromSymbol, symbol);
                if (TRUE == bRet) {
                    context->mssdk.lpfnUnDecorateSymbolName((PCTSTR)symbol->Name, (PTSTR)buffer_undecorated_name, (1 << 10), UNDNAME_NAME_ONLY);
                    context->mssdk.lpfnUnDecorateSymbolName((PCTSTR)symbol->Name, (PTSTR)buffer_undecorated_fullname, (1 << 10), UNDNAME_COMPLETE);
                    stream->printf(constexpr_undeco, bModuleInfoRet ? Module.ModuleName : "", buffer_undecorated_name);
                    if (0 != dwOffsetFromSymbol) {
                        stream->printf(constexpr_fileline, dwOffsetFromSymbol);
                    }
                } else {
                    // bfd
                }

                bRet = context->mssdk.lpfnSymGetLineFromAddr(process_handle, frame.AddrPC.Offset, &dwOffsetFromSymbol, &Line);
                if (TRUE == bRet) {
                    stream->printf(constexpr_line, Line.FileName, Line.LineNumber);
                } else {
                    // bfd
                }
            }

            if (0 == frame.AddrReturn.Offset) {
                SetLastError(0);
                break;
            }

            stream->printf("\n");
        }
    }
    __finally2 {
        if (nullptr != symbol) {
            free(symbol);
        }

        if (errorcode_t::success != ret) {
            // do nothing
        }
    }

    return ret;
}

return_t debug_trace::trace(debug_trace_context_t* handle, EXCEPTION_POINTERS* exception, stream_t* stream) {
    return_t ret = errorcode_t::success;

    backtrace_context_t* context = (backtrace_context_t*)handle;
    IMAGEHLP_SYMBOL* pSymbol = nullptr;

    __try2 {
        if (nullptr == handle || nullptr == exception || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (BACKTRACE_CONTEXT_SIGNATURE != context->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        EXCEPTION_RECORD* exception_record = exception->ExceptionRecord;

        constexpr char constexpr_except[] = "exception\n";
        constexpr char constexpr_except_addr[] = "exception address : 0x%08x\n";
        constexpr char constexpr_except_code[] = "  exception code  : 0x%08x\n";
        constexpr char constexpr_except_flag[] = "  exception flags : 0x%08x\n";
        constexpr char constexpr_except_parm[] = "number parameters : %d\n";
        constexpr char constexpr_except_recd[] = "  parameter [%d]   : 0x%08x\n";

        stream->printf(constexpr_except);
        stream->printf(constexpr_except_addr, exception_record->ExceptionAddress);
        stream->printf(constexpr_except_code, exception_record->ExceptionCode);
        stream->printf(constexpr_except_flag, exception_record->ExceptionFlags);
        stream->printf(constexpr_except_parm, exception_record->NumberParameters);
        for (DWORD i = 0; i < exception_record->NumberParameters; i++) {
            stream->printf(constexpr_except_recd, i, exception_record->ExceptionInformation[i]);
        }

        CONTEXT* rtlcontext = exception->ContextRecord;
        trace(handle, rtlcontext, stream);
    }
    __finally2 {
        if (nullptr != pSymbol) {
            free(pSymbol);
        }

        if (errorcode_t::success != ret) {
            // do nothing
        }
    }

    return ret;
}

LONG __stdcall exception_handler(struct _EXCEPTION_POINTERS* exception_ptr) {
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOALIGNMENTFAULTEXCEPT | SEM_NOOPENFILEERRORBOX);

    LONG lRet = EXCEPTION_EXECUTE_HANDLER;
    DWORD ret = errorcode_t::success;

    __try2 {
        // __try { ... }
        // __except(ExceptionExecuteHandler(GetExceptionInformation())) { ... }

        // write minidump

        /* exception record call stack */
        basic_stream stream;
        debug_trace trace;
        HANDLE thread_handle = nullptr;
        BOOL bRet = TRUE;
        bRet = DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(), &thread_handle, 0, false, DUPLICATE_SAME_ACCESS);
        if (TRUE == bRet) {
            debug_trace_context_t* handle = nullptr;
            trace.open(&handle);
            trace.trace(handle, exception_ptr, &stream);
            trace.close(handle);

            printf("%.*s\n", stream.size(), stream.data());

            CloseHandle(thread_handle);
        }
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            lRet = EXCEPTION_CONTINUE_SEARCH;
        }
    }

    return lRet;
}

LPTOP_LEVEL_EXCEPTION_FILTER old_exception_handler = nullptr;

void set_trace_exception() { old_exception_handler = SetUnhandledExceptionFilter(exception_handler); }
void reset_trace_exception() { SetUnhandledExceptionFilter(old_exception_handler); }

}  // namespace hotplace
