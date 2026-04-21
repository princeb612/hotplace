@echo off

rem run a third-party build manually if necessary.

call "c:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"

set builddir=build_msvc
set generator=Visual Studio 18 2026
set target=Release

mkdir %builddir%
cmake -G "%generator%" -B %builddir% -DCMAKE_BUILD_TYPE=%target% -DCMAKE_POLICY_VERSION_MINIMUM=3.5

cmake --build %builddir% --config %target%

cd %builddir%
ctest -C %target%
