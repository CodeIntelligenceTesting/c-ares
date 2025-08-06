# Copyright (C) The c-ci project and its contributors
# SPDX-License-Identifier: MIT
AUTOMAKE_OPTIONS = foreign subdir-objects nostdinc 1.9.6
ACLOCAL_AMFLAGS = -I m4 --install

# Specify our include paths here, and do it relative to $(top_srcdir) and
# $(top_builddir), to ensure that these paths which belong to the library
# being currently built and tested are searched before the library which
# might possibly already be installed in the system.

AM_CPPFLAGS += -I$(top_builddir)/include \
               -I$(top_builddir)/src/lib \
               -I$(top_srcdir)/include \
               -I$(top_srcdir)/src/lib \
               -I$(top_srcdir)/src/lib/include

lib_LTLIBRARIES = libcci.la

man_MANS = $(MANPAGES)

# adig and ahost are just sample programs and thus not mentioned with the
# regular sources and headers
EXTRA_DIST = Makefile.inc config-win32.h CMakeLists.txt \
  ci_config.h.in ci_config.h.cmake cci.rc \
  $(CSOURCES) $(HHEADERS) config-dos.h

DISTCLEANFILES = ci_config.h

DIST_SUBDIRS =

libcci_la_LDFLAGS = -version-info @CI_VERSION_INFO@
if CI_USE_NO_UNDEFINED
libcci_la_LDFLAGS += -no-undefined
endif

libcci_la_CFLAGS_EXTRA =

libcci_la_CPPFLAGS_EXTRA = -DCI_BUILDING_LIBRARY

if CI_SYMBOL_HIDING
libcci_la_CFLAGS_EXTRA += @CI_SYMBOL_HIDING_CFLAG@
libcci_la_CPPFLAGS_EXTRA += -DCI_SYMBOL_HIDING
endif

include $(top_srcdir)/aminclude_static.am
libcci_la_LIBS = $(CODE_COVERAGE_LIBS)
libcci_la_CFLAGS_EXTRA += $(CODE_COVERAGE_CFLAGS)
libcci_la_CPPFLAGS_EXTRA += $(CODE_COVERAGE_CPPFLAGS)

libcci_la_CFLAGS = $(AM_CFLAGS) $(libcci_la_CFLAGS_EXTRA)

libcci_la_CPPFLAGS = $(AM_CPPFLAGS) $(libcci_la_CPPFLAGS_EXTRA)

# Makefile.inc provides the CSOURCES and HHEADERS defines
include Makefile.inc

libcci_la_SOURCES = $(CSOURCES) $(HHEADERS)
