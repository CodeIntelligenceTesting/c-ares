# Copyright (C) The c-ci project and its contributors
# SPDX-License-Identifier: MIT
# Write ci_build.h configuration file.  This is an installed file.
CONFIGURE_FILE (ci_build.h.cmake ${PROJECT_BINARY_DIR}/ci_build.h)

# Headers installation target
IF (CI_INSTALL)
	SET (CI_HEADERS ci.h ci_version.h "${PROJECT_BINARY_DIR}/ci_build.h" ci_dns.h ci_dns_record.h ci_nameser.h)
	INSTALL (FILES ${CI_HEADERS} COMPONENT Devel DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
ENDIF ()
