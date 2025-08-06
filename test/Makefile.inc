# Copyright (C) The c-ci project and its contributors
# SPDX-License-Identifier: MIT
TESTSOURCES = ci-test-main.cc	\
  ci-test-init.cc			\
  ci-test.cc				\
  ci-test-ns.cc			\
  ci-test-parse.cc			\
  ci-test-parse-a.cc			\
  ci-test-parse-aaaa.cc		\
  ci-test-parse-caa.cc		\
  ci-test-parse-mx.cc		\
  ci-test-parse-naptr.cc		\
  ci-test-parse-ns.cc		\
  ci-test-parse-ptr.cc		\
  ci-test-parse-soa.cc		\
  ci-test-parse-soa-any.cc		\
  ci-test-parse-srv.cc		\
  ci-test-parse-txt.cc		\
  ci-test-parse-uri.cc		\
  ci-test-misc.cc			\
  ci-test-live.cc			\
  ci-test-mock.cc			\
  ci-test-mock-ai.cc			\
  ci-test-mock-et.cc		\
  ci-test-internal.cc		\
  dns-proto.cc				\
  dns-proto-test.cc

TESTHEADERS = ci-test.h		\
  dns-proto.h	\
  ci-test-ai.h

FUZZSOURCES = ci-test-fuzz.c		\
  ci-fuzz.c

FUZZNAMESOURCES = ci-test-fuzz-name.c	\
  ci-fuzz.c

DUMPSOURCES = dns-proto.cc		\
  dns-dump.cc

LOOPSOURCES = ci_queryloop.c
