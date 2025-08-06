# Copyright (C) The c-ci project and its contributors
# SPDX-License-Identifier: MIT
AUTOMAKE_OPTIONS = foreign subdir-objects nostdinc 1.9.6

AM_CPPFLAGS += -I$(top_builddir)/include       \
               -I$(top_builddir)/src/lib       \
               -I$(top_srcdir)/include         \
               -I$(top_srcdir)/src/lib         \
               -I$(top_srcdir)/src/lib/include \
               -I$(top_srcdir)/test            \
               -I$(top_builddir)/test          \
               -I$(top_builddir) -DCI_NO_DEPRECATED

AM_CXXFLAGS :=
AM_CXXFLAGS += $(PTHREAD_CFLAGS)
AM_CFLAGS   += $(PTHREAD_CFLAGS)

# Makefile.inc provides the various *SOURCES and *HEADERS defines
include Makefile.inc

TESTS = citest fuzzcheck.sh

noinst_PROGRAMS = citest cifuzz cifuzzname dnsdump ci_queryloop
EXTRA_DIST = fuzzcheck.sh CMakeLists.txt Makefile.m32 Makefile.msvc README.md $(srcdir)/fuzzinput/* $(srcdir)/fuzznames/*
citest_SOURCES = $(TESTSOURCES) $(TESTHEADERS)

# Not interested in coverage of test code, but linking the test binary needs the coverage option
citest_CXXFLAGS = $(AM_CXXFLAGS) $(GMOCK_CFLAGS)
citest_LDADD = $(GMOCK_LIBS) $(top_builddir)/src/lib/libcci.la $(PTHREAD_LIBS) $(CODE_COVERAGE_LIBS)

cifuzz_SOURCES = $(FUZZSOURCES)
cifuzz_LDADD = $(top_builddir)/src/lib/libcci.la $(PTHREAD_LIBS) $(CODE_COVERAGE_LIBS)

cifuzzname_SOURCES = $(FUZZNAMESOURCES)
cifuzzname_LDADD = $(top_builddir)/src/lib/libcci.la $(PTHREAD_LIBS) $(CODE_COVERAGE_LIBS)

dnsdump_SOURCES = $(DUMPSOURCES)
dnsdump_LDADD = $(top_builddir)/src/lib/libcci.la $(PTHREAD_LIBS) $(CODE_COVERAGE_LIBS)

ci_queryloop_SOURCES = $(LOOPSOURCES)
ci_queryloop_LDADD = $(top_builddir)/src/lib/libcci.la $(PTHREAD_LIBS) $(CODE_COVERAGE_LIBS)

test: check
