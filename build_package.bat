@echo off
rem Build the pip package (wheel + source archive) into dist\  - needs Python 3.9+
setlocal
cd /d "%~dp0"
set "PY=py -3"
where py >nul 2>nul || set "PY=python"
%PY% -m pip install --disable-pip-version-check --quiet --upgrade build twine || goto :fail
if exist dist\*.whl del /q dist\*.whl
if exist dist\*.tar.gz del /q dist\*.tar.gz
%PY% -m build || goto :fail
%PY% -m twine check dist\*.whl dist\*.tar.gz || goto :fail
echo.
echo Package built in dist\ . Upload: see PUBLISHING.md
pause
exit /b 0
:fail
echo Build FAILED.
pause
exit /b 1
