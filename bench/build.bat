@echo off
REM LUCENT M2 fixture build - the stack-overflow baseline.
REM
REM Compiles the VENDORED stack-overflow fixture (bench\vuln.c: a 16-byte stack
REM buffer + unbounded strcpy) into vuln.exe + vuln.pdb in the sandbox. The
REM source is vendored INTO this repo (from BugMuseum) so the build works on the
REM target VM, which does NOT have BugMuseum checked out. Pass a path as arg 1 to
REM compile a different src.c instead (e.g. the museum copy on the dev box).
REM
REM Flags:
REM   /Zi /Fd : emit vuln.pdb next to the exe so cdb resolves vuln!vuln
REM             (BugMuseum's own build.ps1 ships NO pdb; we build our own here so
REM              the reached_sink() TTD milestone can name the sink).
REM   /Od     : keep the frame + the strcpy; textbook, un-optimized shape.
REM   /GS-    : NO stack cookie. The overflow overwrites the saved return
REM             address, so `ret` faults with an ACCESS VIOLATION that the
REM             oracle's `sxe av` catches. (The /GS build fail-fasts with
REM             STATUS_STACK_BUFFER_OVERRUN instead - that is the next rung up
REM             the ladder, not this baseline.)
REM
REM NO page heap here: page heap instruments the HEAP; it does nothing for a
REM stack overflow. That apparatus comes back for the heap/UAF museum variants.
REM
REM Forces an x64 toolchain so vuln.exe matches the x64 VM (avoids
REM ERROR_EXE_MACHINE_TYPE_MISMATCH / Win32 0n216). Can be run from a PLAIN cmd
REM prompt - it sets up vcvars64 itself.

setlocal enabledelayedexpansion
set "OUT=C:\lucent\sandbox"
if not exist "%OUT%" mkdir "%OUT%"

REM --- Source: the vendored fixture next to this script (overridable as arg 1) -
set "SRC=%~1"
if not defined SRC set "SRC=%~dp0vuln.c"
if not exist "!SRC!" ( echo [build] ERROR: source not found: !SRC! & exit /b 1 )
echo [build] source: !SRC!

REM --- Locate VS and enter the x64 build environment -------------------------
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "!VSWHERE!" set "VSWHERE=%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe"
set "VSPATH="
if exist "!VSWHERE!" (
    for /f "usebackq tokens=*" %%i in (`"!VSWHERE!" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSPATH=%%i"
)
if defined VSPATH (
    call "!VSPATH!\VC\Auxiliary\Build\vcvars64.bat" >nul
    echo [build] x64 toolchain: !VSPATH!
) else (
    echo [build] WARNING: vswhere not found - relying on cl already on PATH.
    echo [build]          If the arch check below is not x64, use an x64 Native Tools prompt.
)

where cl >nul 2>nul || ( echo [build] ERROR: cl.exe not on PATH. & exit /b 1 )

REM --- Build config -----------------------------------------------------------
REM   default          -> /Od /GS-  (no cookie): overflow overwrites the return
REM                       address, `ret` faults with an ACCESS VIOLATION.  vuln.exe
REM   LUCENT_BUILD=gs  -> /Od /GS   (stack cookie): overflow trips __security_check
REM                       _cookie, which __fastfails with STATUS_STACK_BUFFER_OVERRUN
REM                       (0xc0000409) BEFORE `ret` - a crash with NO hijack.  vuln_gs.exe
REM   (Uses /Od, not /O2, on purpose: at /O2 the optimizer can dead-code-eliminate
REM    this trivial buf/strcpy so it never overflows. /Od guarantees the overrun,
REM    and the /GS cookie is inserted regardless of opt level.)
REM Both keep /Zi so cdb resolves <module>!vuln.
set "CFLAGS=/Zi /Od /GS-"
set "EXE=vuln.exe"
set "OBJ=vuln.obj"
set "PDB=vuln.pdb"
set "DESC=/Od /GS-  no cookie, return-address AV"
if /i "!LUCENT_BUILD!"=="gs" (
    set "CFLAGS=/Zi /Od /GS"
    set "EXE=vuln_gs.exe"
    set "OBJ=vuln_gs.obj"
    set "PDB=vuln_gs.pdb"
    set "DESC=/Od /GS  stack cookie, fail-fast on overflow"
)
echo [build] config: !DESC!

REM Clear prior outputs FIRST, so a failed build cannot leave a stale/garbage exe
REM behind for verify_oracle.py to run (that shows up as "unsupported 16-bit
REM application" / not-a-PE). After this, the exe existing == build OK.
del /q "%OUT%\!EXE!" "%OUT%\!OBJ!" "%OUT%\!PDB!" 2>nul

cl /nologo !CFLAGS! "!SRC!" ^
   /Fe:"%OUT%\!EXE!" /Fo:"%OUT%\!OBJ!" /Fd:"%OUT%\!PDB!" ^
   /link /DEBUG
if errorlevel 1 ( echo. & echo [build] FAILED - see cl output above. & exit /b 1 )
if not exist "%OUT%\!EXE!" ( echo. & echo [build] FAILED - no !EXE! produced. & exit /b 1 )

REM --- Self-report the produced architecture (the decisive sanity check) -----
echo.
python "%~dp0archcheck.py" "%OUT%\!EXE!"
echo.
echo [build] OK: %OUT%\!EXE!  (plus !PDB!)
echo [build] next: python bench\verify_oracle.py --no-ttd
echo [build]       (for the /GS build: set LUCENT_IMAGE=!EXE! first)
endlocal
