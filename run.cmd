@echo off
setlocal
set "PY="
where py >nul 2>nul
if not errorlevel 1 (
  py -3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>nul
  if not errorlevel 1 set "PY=py -3"
)
if not defined PY (
  where python >nul 2>nul
  if not errorlevel 1 (
    python -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>nul
    if not errorlevel 1 set "PY=python"
  )
)
if not defined PY (
  echo Error: Assay needs Python 3.10 or newer. 1>&2
  echo Why: no working Python 3.10+ interpreter was found on PATH. 1>&2
  echo Fix: install Python 3.10+ and rerun run.cmd. 1>&2
  exit /b 2
)
if "%~1"=="" (
  %PY% -m assay demo
) else (
  %PY% -m assay %*
)
exit /b %errorlevel%
