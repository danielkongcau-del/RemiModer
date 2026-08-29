@echo off
setlocal EnableExtensions EnableDelayedExpansion
if not defined VCToolsInstallDir (
  set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
  if not exist "!VSWHERE!" exit /b 1
  for /f "usebackq tokens=*" %%i in (`"!VSWHERE!" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSROOT=%%i"
  if not defined VSROOT exit /b 1
  call "!VSROOT!\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
  if errorlevel 1 exit /b 1
)
cd /d "%~dp0"
if not exist build mkdir build
set "UC_INC=/Ivendor /Ivendor\gum-17.17.0 /Inative"
set "UC_COMMON=native\common.cpp native\modules.cpp"
ml64 /nologo /c /Fo build\pair_runtime_fixture.obj native\pair_runtime_fixture.asm
if errorlevel 1 exit /b 1
cl /nologo /std:c++20 /utf-8 /O2 /W4 /MT /EHsc /DGUM_STATIC %UC_INC% /LD %UC_COMMON% native\store.cpp native\plan.cpp native\readers.cpp native\runtime.cpp native\legacy.cpp native\agent.cpp /Fo:build\ /Fe:build\UnifiedCapture.dll /link /INCREMENTAL:NO /LIBPATH:vendor\gum-17.17.0 frida-gum.lib Bcrypt.lib Cabinet.lib Psapi.lib Dnsapi.lib Iphlpapi.lib Winmm.lib Ws2_32.lib Shlwapi.lib Advapi32.lib Ole32.lib Shell32.lib User32.lib
if errorlevel 1 exit /b 1
cl /nologo /std:c++20 /utf-8 /O2 /W4 /MT /EHsc %UC_INC% native\fixture.cpp build\pair_runtime_fixture.obj %UC_COMMON% /Fo:build\ /Fe:build\FixtureHost.exe /link /INCREMENTAL:NO Bcrypt.lib Cabinet.lib Psapi.lib
if errorlevel 1 exit /b 1
cl /nologo /std:c++20 /utf-8 /O2 /W4 /MT /EHsc /LD native\fixture_module.cpp /Fo:build\ /Fe:build\FixtureModule.dll /link /INCREMENTAL:NO
if errorlevel 1 exit /b 1
ml64 /nologo /c /Fo build\probe_pair_fixture.obj native\probe_pair_fixture.asm
if errorlevel 1 exit /b 1
cl /nologo /std:c++20 /utf-8 /O2 /W4 /MT /EHsc /DGUM_STATIC %UC_INC% native\probe_pair_probe.cpp build\probe_pair_fixture.obj %UC_COMMON% /Fo:build\ /Fe:build\ProbePairProbe.exe /link /INCREMENTAL:NO /LIBPATH:vendor\gum-17.17.0 frida-gum.lib Bcrypt.lib Cabinet.lib Psapi.lib Dnsapi.lib Iphlpapi.lib Winmm.lib Ws2_32.lib Shlwapi.lib Advapi32.lib Ole32.lib Shell32.lib User32.lib
if errorlevel 1 exit /b 1
cl /nologo /std:c++20 /utf-8 /O2 /W4 /MT /EHsc /Inative native\pairing_probe.cpp /Fo:build\ /Fe:build\PairLedgerProbe.exe /link /INCREMENTAL:NO
if errorlevel 1 exit /b 1
cl /nologo /std:c++20 /utf-8 /O2 /W4 /MT /EHsc /Ivendor /Inative native\store_probe.cpp %UC_COMMON% native\store.cpp /Fo:build\ /Fe:build\StoreProbe.exe /link /INCREMENTAL:NO Bcrypt.lib Cabinet.lib Psapi.lib
exit /b %errorlevel%
