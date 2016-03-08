CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT(test_app2ext C)

SET(SOURCE_DIR ${CMAKE_SOURCE_DIR})

SET(SRCS
	${SOURCE_DIR}/test/src/test_app2ext.c
)

INCLUDE(FindPkgConfig)
pkg_check_modules(pkgs REQUIRED dlog)

FOREACH(flag ${pkgs_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

pkg_check_modules(libpkgs REQUIRED dlog)

FOREACH(flag ${libpkgs_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

### Local include directories
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/inc)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIE ${EXTRA_CFLAGS}")
SET(CMAKE_C_FLAGS_DEBUG "-O0 -g -Wall -Wextra -fPIE")
SET(CMAKE_C_FLAGS_RELEASE "-O3 -fPIE")

ADD_EXECUTABLE(test_app2ext ${SRCS})
TARGET_LINK_LIBRARIES(test_app2ext app2ext -ldl ${pkgs_LDFLAGS} "-pie")

INSTALL(TARGETS test_app2ext DESTINATION /usr/bin COMPONENT Runtime)

