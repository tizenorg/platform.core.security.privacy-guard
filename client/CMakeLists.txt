CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
#PROJECT(privacy-guard-client)

SET(CMAKE_INSTALL_PREFIX /usr)
SET(PREFIX ${CMAKE_INSTALL_PREFIX})
SET(EXEC_PREFIX "\${prefix}")
SET(LIBDIR ${LIB_INSTALL_DIR})
SET(INCLUDEDIR ${INCLUDE_INSTALL_DIR})

INCLUDE(FindPkgConfig)
pkg_check_modules(privacy-guard-client REQUIRED dlog sqlite3 dbus-1 dbus-glib-1 db-util pkgmgr-info libtzplatform-config)

FOREACH(flag ${pkgs_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

SET(CMAKE_C_FLAGS_PROFILING    " -g -pg")
SET(CMAKE_CXX_FLAGS_PROFILING  " -std=c++0x -g -pg")
SET(CMAKE_C_FLAGS_DEBUG        " -g")
SET(CMAKE_CXX_FLAGS_DEBUG      " -std=c++0x -g")
SET(CMAKE_C_FLAGS_RELEASE      " -g")
SET(CMAKE_CXX_FLAGS_RELEASE    " -std=c++0x -g")
SET(CMAKE_C_FLAGS_CCOV         " -g --coverage")
SET(CMAKE_CXX_FLAGS_CCOV       " -std=c++0x -g --coverage")

SET(client_src_dir "${CMAKE_SOURCE_DIR}/client/src")
SET(client_include_dir "${CMAKE_SOURCE_DIR}/client/inc/")
SET(common_src_dir "${CMAKE_SOURCE_DIR}/common/src/")
SET(common_include_dir "${CMAKE_SOURCE_DIR}/common/inc/")
SET(extern_include_dir "${CMAKE_SOURCE_DIR}/include/")

## Additional flag
ADD_DEFINITIONS("-fvisibility=hidden")
ADD_DEFINITIONS("-Wall -Werror")
ADD_DEFINITIONS("-DDLOG_ERROR_ENABLED")
ADD_DEFINITIONS("-D_PRIVACY_GUARD_DEBUG")
OPTION (FILTER_LISTED_PKG "FILTER PKG BY LIST" ON)
IF(FILTER_LISTED_PKG)
    MESSAGE("FILTER PKGs BY FILTERING LIST")
    ADD_DEFINITIONS("-D__FILTER_LISTED_PKG")
ENDIF(FILTER_LISTED_PKG)
## SET PRIVACY_POPUP FLAG
OPTION (PRIVACY_POPUP "PRIVACY_POPUP" ON)
IF(PRIVACY_POPUP)
	MESSAGE("PRIVACY_POPUP IS ENABLED")
	ADD_DEFINITIONS("-D__PRIVACY_POPUP")
ENDIF(PRIVACY_POPUP)

###################################################################################################
## for libprivacy-guard-client
INCLUDE_DIRECTORIES(${pkgs_INCLUDE_DIRS} ${client_include_dir} ${common_include_dir} ${extern_include_dir})
SET(PRIVACY_GUARD_CLIENT_SOURCES
	${common_src_dir}/SocketConnection.cpp
	${common_src_dir}/SocketStream.cpp
	${common_src_dir}/PrivacyIdInfo.cpp
	${client_src_dir}/SocketClient.cpp
	${client_src_dir}/PrivacyChecker.cpp
	${client_src_dir}/PrivacyGuardClient.cpp
	${client_src_dir}/privacy_guard_client.cpp
	)
SET(PRIVACY_GUARD_CLIENT_HEADERS
	${client_include_dir}/PrivacyChecker.h
	${client_include_dir}/PrivacyGuardClient.h
	${client_include_dir}/privacy_guard_client_internal.h
	)
SET(PRIVACY_GUARD_EXTERN_HEADERS
	${extern_include_dir}/privacy_guard_client.h
	${extern_include_dir}/privacy_guard_client_types.h
	)

SET(PRIVACY_GUARD_CLIENT_LDFLAGS " -module -avoid-version ")
SET(PRIVACY_GUARD_CLIENT_CFLAGS  " ${CFLAGS} -fPIC ")

ADD_DEFINITIONS("-DLOG_TAG=\"PRIVACY-GUARD-CLIENT\"")
ADD_LIBRARY(privacy-guard-client SHARED ${PRIVACY_GUARD_CLIENT_SOURCES})
TARGET_LINK_LIBRARIES(privacy-guard-client ${pkgs_LDFLAGS} ${pkgs_LIBRARIES})
SET_TARGET_PROPERTIES(privacy-guard-client PROPERTIES COMPILE_FLAGS "${PRIVACY_GUARD_CLIENT_CFLAGS}")
SET_TARGET_PROPERTIES(privacy-guard-client PROPERTIES SOVERSION ${API_VERSION})
SET_TARGET_PROPERTIES(privacy-guard-client PROPERTIES VERSION ${VERSION})
###################################################################################################

SET(PC_NAME privacy-guard-client)
SET(PC_DESCRIPTION "Privacy Guard Client API")
SET(PC_LDFLAGS -lprivacy-guard-client)
SET(PC_CFLAGS -I\${includedir}/privacy_guard)

CONFIGURE_FILE(../privacy-guard-client.pc.in privacy-guard-client.pc @ONLY)

INSTALL(TARGETS privacy-guard-client DESTINATION ${LIB_INSTALL_DIR} COMPONENT RuntimeLibraries)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/privacy-guard-client.pc DESTINATION ${LIB_INSTALL_DIR}/pkgconfig)
INSTALL(FILES ${PRIVACY_GUARD_CLIENT_HEADERS} DESTINATION ${INCLUDE_INSTALL_DIR}/privacy_guard/client)
INSTALL(FILES ${PRIVACY_GUARD_EXTERN_HEADERS} DESTINATION ${INCLUDE_INSTALL_DIR}/privacy_guard)