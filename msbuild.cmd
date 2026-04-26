@echo off

rem run a third-party build manually if necessary.

if not defined VSINSTALLDIR (
  call "c:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
)

set builddir=build_msvc
set generator=Visual Studio 18 2026
set target=Release

if not exist %builddir% (
  mkdir %builddir%
)

cmake -G "%generator%" -B %builddir% -DCMAKE_BUILD_TYPE=%target% -DCMAKE_POLICY_VERSION_MINIMUM=3.5 -DSUPPORT_PCH=1

cmake --build %builddir% --config %target%

cd %builddir%
ctest -C %target%
cd ..
