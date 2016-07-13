# Required packages
pkg_check_modules(test_pkgs REQUIRED dlog zlib minizip storage glib-2.0)

FOREACH(flag ${test_pkgs_CFLAGS})
	SET(TEST_CFLAGS "${TEST_CFLAGS} ${flag}")
ENDFOREACH(flag)
SET(CMAKE_C_FLAGS "${EXTRA_CFLAGS} ${TEST_CFLAGS}")

# Local include directories
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/inc)

SET(SRCS ${CMAKE_SOURCE_DIR}/test/src/test_app2ext.c)

ADD_EXECUTABLE(test_app2ext ${SRCS})
TARGET_LINK_LIBRARIES(test_app2ext app2ext ${test_pkgs_LDFLAGS})
SET_TARGET_PROPERTIES(test_app2ext PROPERTIES COMPILE_FLAGS ${CFLAGS} "-fPIE")
SET_TARGET_PROPERTIES(test_app2ext PROPERTIES LINK_FLAGS "-pie")

INSTALL(TARGETS test_app2ext DESTINATION /usr/bin COMPONENT Runtime)
