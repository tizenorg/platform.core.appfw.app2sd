CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT(app2sd C)

### Required packages
INCLUDE(FindPkgConfig)
pkg_check_modules(pkgs REQUIRED libssl dlog openssl pkgmgr-info libtzplatform-config gio-2.0 glib-2.0 minizip)

FOREACH(flag ${pkgs_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

pkg_check_modules(libpkgs REQUIRED libssl dlog openssl pkgmgr-info db-util gio-2.0 glib-2.0 minizip)

FOREACH(flag ${libpkgs_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -fvisibility=hidden -Wno-unused-result")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS}")

### Local include directories
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/inc
		${CMAKE_SOURCE_DIR}/src)

SET(app2sd_dir "${CMAKE_SOURCE_DIR}/plugin/app2sd")
SET(app2sd_inc_dir "${app2sd_dir}/inc")
SET(app2sd_src_dir "${app2sd_dir}/src")

## build app2sd library
SET(APP2SD "app2sd")
SET(libapp2sd_SOURCES
	${app2sd_src_dir}/app2sd_client_interface.c)
SET(libapp2sd_LDFLAGS " -L${LIB_INSTALL_DIR} -lcrypto -module -avoid-version ")
SET(libapp2sd_CFLAGS  " ${CFLAGS} -fPIC -I${app2sd_inc_dir} ")

ADD_LIBRARY(${APP2SD} SHARED ${libapp2sd_SOURCES})
SET_TARGET_PROPERTIES(${APP2SD} PROPERTIES SOVERSION ${VERSION_MAJOR})
SET_TARGET_PROPERTIES(${APP2SD} PROPERTIES VERSION ${VERSION})
SET_TARGET_PROPERTIES(${APP2SD} PROPERTIES COMPILE_FLAGS "${libapp2sd_CFLAGS}")
TARGET_LINK_LIBRARIES(${APP2SD} ${libpkgs_LDFLAGS} "-lm")

## devel package

SET(CMAKE_INSTALL_PREFIX "/usr")
SET(PREFIX ${CMAKE_INSTALL_PREFIX})

INSTALL(TARGETS ${APP2SD} DESTINATION ${LIB_INSTALL_DIR} COMPONENT RuntimeLibraries)

## build app2sd-server binary
SET(APP2SD_SERVER "app2sd-server")
SET(app2sd_server_SOURCES
	${app2sd_src_dir}/app2sd_internals.c
	${app2sd_src_dir}/app2sd_interface.c
	${app2sd_src_dir}/app2sd_internals_registry.c
	${app2sd_src_dir}/app2sd_internals_utils.c
	${app2sd_src_dir}/app2sd_server.c)
ADD_EXECUTABLE(${APP2SD_SERVER} ${app2sd_server_SOURCES})
SET_TARGET_PROPERTIES(${APP2SD_SERVER} PROPERTIES COMPILE_FLAGS ${CFLAGS} "-fPIE -I${app2sd_inc_dir} ")
SET_TARGET_PROPERTIES(${APP2SD_SERVER} PROPERTIES LINK_FLAGS "-pie")
TARGET_LINK_LIBRARIES(${APP2SD_SERVER} app2sd ${pkgs_LDFLAGS})

CONFIGURE_FILE(org.tizen.app2sd.service.in org.tizen.app2sd.service @ONLY)
CONFIGURE_FILE(org.tizen.app2sd.conf.in org.tizen.app2sd.conf @ONLY)

INSTALL(TARGETS ${APP2SD_SERVER} DESTINATION bin)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/org.tizen.app2sd.service DESTINATION
	${PREFIX}/share/dbus-1/system-services/)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/org.tizen.app2sd.conf DESTINATION
	${SYSCONF_INSTALL_DIR}/dbus-1/system.d/)
