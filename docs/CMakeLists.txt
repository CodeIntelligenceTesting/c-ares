# Copyright (C) The c-ci project and its contributors
# SPDX-License-Identifier: MIT
# Headers and Man Pages installation target
IF (CI_INSTALL)
	# ManPages
	FILE (GLOB DevelManPages "." "*.3")
	INSTALL (FILES ${DevelManPages}
		DESTINATION ${CMAKE_INSTALL_MANDIR}/man3
		COMPONENT Devel
	)

	IF (CI_BUILD_TOOLS)
		FILE (GLOB ToolManPages "." "*.1")
		INSTALL (FILES ${ToolManPages}
			DESTINATION ${CMAKE_INSTALL_MANDIR}/man1
			COMPONENT Tools
		)
	ENDIF ()
ENDIF ()
