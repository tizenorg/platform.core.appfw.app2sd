CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT(app2sd C)

### Required packages
INCLUDE(FindPkgConfig)
pkg_check_modules(pkgs REQUIRED libssl dlog openssl db-util pkgmgr-info vconf libprivilege-control libtzplatform-config)

FOREACH(flag ${pkgs_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

pkg_check_modules(libpkgs REQUIRED libssl dlog openssl db-util pkgmgr-info vconf libprivilege-control)

FOREACH(flag ${libpkgs_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -fvisibility=hidden -Wno-unused-result")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS}")

### Local include directories
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/inc ${CMAKE_SOURCE_DIR}/src)

## build app2sd library
SET(app2sd_dir "${CMAKE_SOURCE_DIR}/plugin/app2sd")
SET(app2sd_inc_dir "${app2sd_dir}/inc")
SET(app2sd_src_dir "${app2sd_dir}/src")
SET(APP2SD "app2sd")
SET(libapp2sd_SOURCES ${app2sd_src_dir}/app2sd_internals.c ${app2sd_src_dir}/app2sd_interface.c ${app2sd_src_dir}/app2sd_internals_registry.c ${app2sd_src_dir}/app2sd_internals_utils.c)
SET(libapp2sd_LDFLAGS " -L${LIB_INSTALL_DIR} -lcrypto -module -avoid-version ")
SET(libapp2sd_CFLAGS  " ${CFLAGS} -fPIC -I${app2sd_inc_dir} ")

ADD_LIBRARY(${APP2SD} SHARED ${libapp2sd_SOURCES})
SET_TARGET_PROPERTIES(${APP2SD} PROPERTIES SOVERSION ${VERSION_MAJOR})
SET_TARGET_PROPERTIES(${APP2SD} PROPERTIES VERSION ${VERSION})
SET_TARGET_PROPERTIES(${APP2SD} PROPERTIES COMPILE_FLAGS "${libapp2sd_CFLAGS}")
TARGET_LINK_LIBRARIES(${APP2SD} ${libpkgs_LDFLAGS} "-lm")

SET(CMAKE_INSTALL_PREFIX "/usr")
SET(PREFIX ${CMAKE_INSTALL_PREFIX})


INSTALL(TARGETS ${APP2SD} DESTINATION ${LIB_INSTALL_DIR} COMPONENT RuntimeLibraries)


