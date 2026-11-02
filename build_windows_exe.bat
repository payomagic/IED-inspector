@echo off
rem ===========================================================================
rem  IED Inspector - build a single IEDInspector.exe for Windows
rem
rem  Run this ONCE on a Windows PC that has Python 3.9+ (python.org installer,
rem  "Add python.exe to PATH" ticked). Internet access to pypi.org is needed
rem  the first time to download PyInstaller.
rem
rem  Result: dist\IEDInspector.exe  - copy that one file to any Windows 10/11
rem  PC. It runs WITHOUT Python. (Live capture / GOOSE publishing still needs
rem  the Npcap driver on the target PC: https://npcap.com)
rem ===========================================================================
setlocal
cd /d "%~dp0"

rem ---- find Python ----------------------------------------------------------
set "PY="
where py >nul 2>nul && set "PY=py -3"
if not defined PY ( where python >nul 2>nul && set "PY=python" )
if not defined PY (
  echo [ERROR] Python 3.9+ was not found. Install it from https://www.python.org/downloads/
  echo         and tick "Add python.exe to PATH". Python is only needed for building.
  goto :fail
)
%PY% -c "import sys; sys.exit(0 if sys.version_info >= (3,9) else 1)" || (
  echo [ERROR] Python 3.9 or newer is required.
  goto :fail
)

rem ---- isolated build environment ------------------------------------------
if not exist ".build-venv\Scripts\python.exe" (
  echo Creating build environment .build-venv ...
  %PY% -m venv .build-venv || goto :fail
)
set "VPY=.build-venv\Scripts\python.exe"
echo Installing / updating PyInstaller ...
"%VPY%" -m pip install --disable-pip-version-check --quiet --upgrade pip || goto :fail
"%VPY%" -m pip install --disable-pip-version-check --quiet "pyinstaller>=6.3" "pywebview>=5.0" || goto :fail

rem ---- build ------------------------------------------------------------------
echo Building IEDInspector.exe ...
if exist build rmdir /s /q build
if exist dist\IEDInspector.exe del /q dist\IEDInspector.exe
"%VPY%" -m PyInstaller --noconfirm --clean --onefile --console ^
  --name IEDInspector ^
  --icon "assets\IEDInspector.ico" ^
  --add-data "ied_inspector\web;ied_inspector\web" ^
  --add-data "ied_inspector\examples;ied_inspector\examples" ^
  --add-data "ied_inspector\assets;ied_inspector\assets" ^
  --hidden-import webview.platforms.edgechromium ^
  --hidden-import webview.platforms.winforms ^
  --collect-data webview ^
  --collect-binaries webview ^
  --collect-all clr_loader ^
  --collect-all pythonnet ^
  --hidden-import clr ^
  --collect-submodules ied_inspector ^
  run.py || goto :fail

rem ---- package next to the exe ---------------------------------------------------
copy /y README.md dist\README.md >nul
if not exist dist\examples mkdir dist\examples
copy /y ied_inspector\examples\*.scd dist\examples\ >nul
if exist build rmdir /s /q build
if exist IEDInspector.spec del /q IEDInspector.spec

echo.
echo ===========================================================================
echo  Done:  %cd%\dist\IEDInspector.exe
echo  Copy this single file to the target PC and double-click it.
echo  A start dialog asks: desktop window or web browser (IEDInspector.exe --gui / --web skip it).
echo  Desktop mode uses Microsoft Edge WebView2 (built into Windows 10/11).
echo.
echo  Checking the desktop mode of the new exe:
dist\IEDInspector.exe --diag
echo  Options:  IEDInspector.exe --help
echo ===========================================================================
pause
exit /b 0

:fail
echo.
echo Build FAILED - see the messages above.
pause
exit /b 1
