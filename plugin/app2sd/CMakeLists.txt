# Required packages
pkg_check_modules(app2sd_pkgs REQUIRED dlog pkgmgr-info gio-2.0 glib-2.0 db-util libtzplatform-config aul storage security-manager)
pkg_check_modules(app2sd_libpkgs REQUIRED dlog pkgmgr-info gio-2.0 glib-2.0)

# Compiler flags
FOREACH(flag ${app2sd_pkgs_CFLAGS})
	SET(APP2SD_CFLAGS "${APP2SD_CFLAGS} ${flag}")
ENDFOREACH(flag)
FOREACH(flag ${app2sd_libpkgs_CFLAGS})
	SET(APP2SD_CFLAGS "${APP2SD_CFLAGS} ${flag}")
ENDFOREACH(flag)
SET(CMAKE_C_FLAGS "${EXTRA_CFLAGS} ${APP2SD_CFLAGS}")

# Local include directories
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/inc
	${CMAKE_SOURCE_DIR}/common/inc
	${CMAKE_SOURCE_DIR}/plugin/app2sd/inc)

# build app2sd library
SET(APP2SD "app2sd")
SET(app2sd_src_dir "${CMAKE_SOURCE_DIR}/plugin/app2sd/src")
SET(libapp2sd_SOURCES
	${app2sd_src_dir}/app2sd_client_interface.c
	${CMAKE_SOURCE_DIR}/common/src/app2ext_utils.c)

ADD_LIBRARY(${APP2SD} SHARED ${libapp2sd_SOURCES})
SET_TARGET_PROPERTIES(${APP2SD} PROPERTIES SOVERSION ${VERSION_MAJOR})
SET_TARGET_PROPERTIES(${APP2SD} PROPERTIES VERSION ${VERSION})
SET_TARGET_PROPERTIES(${APP2SD} PROPERTIES COMPILE_FLAGS ${CFLAGS} "-fPIC")
TARGET_LINK_LIBRARIES(${APP2SD} ${app2sd_libpkgs_LDFLAGS})

INSTALL(TARGETS ${APP2SD} DESTINATION ${LIB_INSTALL_DIR} COMPONENT RuntimeLibraries)

# build app2sd-server binary
SET(APP2SD_SERVER "app2sd-server")
SET(app2sd_server_SOURCES
	${app2sd_src_dir}/app2sd_internals.c
	${app2sd_src_dir}/app2sd_interface.c
	${app2sd_src_dir}/app2sd_internals_registry.c
	${app2sd_src_dir}/app2sd_internals_utils.c
	${app2sd_src_dir}/app2sd_server.c
	${CMAKE_SOURCE_DIR}/common/src/app2ext_utils.c)
ADD_EXECUTABLE(${APP2SD_SERVER} ${app2sd_server_SOURCES})
SET_TARGET_PROPERTIES(${APP2SD_SERVER} PROPERTIES COMPILE_FLAGS ${CFLAGS} "-fPIE ")
SET_TARGET_PROPERTIES(${APP2SD_SERVER} PROPERTIES LINK_FLAGS "-pie")
TARGET_LINK_LIBRARIES(${APP2SD_SERVER} app2sd ${app2sd_pkgs_LDFLAGS} "-lm")

CONFIGURE_FILE(org.tizen.app2sd.service.in org.tizen.app2sd.service @ONLY)
CONFIGURE_FILE(org.tizen.app2sd.conf.in org.tizen.app2sd.conf @ONLY)
CONFIGURE_FILE(app2sd-server.service.in app2sd-server.service @ONLY)

INSTALL(TARGETS ${APP2SD_SERVER} DESTINATION bin)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/org.tizen.app2sd.service DESTINATION
	${CMAKE_INSTALL_PREFIX}/share/dbus-1/system-services/)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/org.tizen.app2sd.conf DESTINATION
	${SYSCONF_INSTALL_DIR}/dbus-1/system.d/)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/app2sd-server.service DESTINATION ${UNITDIR})
