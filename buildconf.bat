@echo off
REM
REM
REM This batch file must be used to set up a git tree to build on
REM systems where there is no autotools support (i.e. Microsoft).
REM
REM This file is not included nor needed for c-ci' release
REM archives, neither for c-ci' daily snapshot archives.
REM
REM Copyright (C) The c-ci project and its contributors
REM SPDX-License-Identifier: MIT

if exist GIT-INFO goto start_doing
ECHO ERROR: This file shall only be used with a c-ci git checkout.
goto end_all
:start_doing

if not exist include\ci_build.h.dist goto end_ci_build_h
copy /Y include\ci_build.h.dist include\ci_build.h
:end_ci_build_h

:end_all

