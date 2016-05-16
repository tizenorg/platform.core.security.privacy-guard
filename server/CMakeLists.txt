CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT(privacy-guard)

SET(CMAKE_INSTALL_PREFIX /usr)
SET(PREFIX ${CMAKE_INSTALL_PREFIX})
SET(EXEC_PREFIX "\${prefix}")
SET(INCLUDEDIR "\${prefix}/include")

INCLUDE(FindPkgConfig)
pkg_check_modules(pkgs REQUIRED dlog sqlite3 dbus-1 dbus-glib-1 db-util pkgmgr-info capi-system-info libtzplatform-config security-privilege-manager cynara-monitor)

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

SET(server_src_dir "${CMAKE_SOURCE_DIR}/server/src")
SET(server_include_dir "${CMAKE_SOURCE_DIR}/server/inc/")
SET(common_src_dir "${CMAKE_SOURCE_DIR}/common/src/")
SET(common_include_dir "${CMAKE_SOURCE_DIR}/common/inc/")
SET(extern_include_dir "${CMAKE_SOURCE_DIR}/include/")
SET(dbus_include_dir "/usr/include/dbus-1.0")

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

###################################################################################################
## for privacy-guard-server (executable)
INCLUDE_DIRECTORIES(
	${pkgs_INCLUDE_DIRS}
	${server_include_dir}
	${common_include_dir}
	${extern_include_dir}
	${dbus_include_dir}
	)

SET(PRIVACY_GUARD_SERVER_SOURCES 
	${common_src_dir}/SocketConnection.cpp
	${common_src_dir}/SocketStream.cpp
	${common_src_dir}/PrivacyIdInfo.cpp	
	${server_src_dir}/PrivacyGuardDb.cpp
	${server_src_dir}/main.cpp
	${server_src_dir}/SocketService.cpp
#	${server_src_dir}/CynaraService.cpp
	${server_src_dir}/PrivacyGuardDaemon.cpp
	${server_src_dir}/service/PrivacyInfoService.cpp
	${server_src_dir}/NotificationServer.cpp
	)
SET(PRIVACY_GUARD_SERVER_LDFLAGS " -module -avoid-version ")
SET(PRIVACY_GUARD_SERVER_CFLAGS  " ${CFLAGS} -fPIE ")
#SET(PRIVACY_GUARD_SERVER_LIBADD " ")

ADD_DEFINITIONS("-DLOG_TAG=\"PRIVACY-GUARD-SERVER\"")
ADD_EXECUTABLE(privacy-guard-server ${PRIVACY_GUARD_SERVER_SOURCES})
TARGET_LINK_LIBRARIES(privacy-guard-server ${pkgs_LDFLAGS} ${pkgs_LIBRARIES} "-ldl -pie -lpthread")
SET_TARGET_PROPERTIES(privacy-guard-server PROPERTIES COMPILE_FLAGS "${PRIVACY_GUARD_SERVER_CFLAGS}")
#SET_TARGET_PROPERTIES(privacy-guard-server PROPERTIES SOVERSION ${API_VERSION})
#SET_TARGET_PROPERTIES(privacy-guard-server PROPERTIES VERSION ${VERSION})
###################################################################################################

SET(PC_NAME privacy-guard-server)
SET(PC_DESCRIPTION "Privacy Guard Server API")
SET(PC_LDFLAGS -lprivacy-guard-server)
SET(PC_CFLAGS -I\${includedir}/privacy_guard)

CONFIGURE_FILE(../privacy-guard-server.pc.in privacy-guard-server.pc @ONLY)

INSTALL(TARGETS privacy-guard-server DESTINATION /usr/bin COMPONENT RuntimeLibraries)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/privacy-guard-server.pc DESTINATION ${LIB_INSTALL_DIR}/pkgconfig)
#INSTALL(FILES ${PRIVACY_GUARD_SERVER_HEADERS} DESTINATION ${INCLUDE_INSTALL_DIR}/privacy_guard/server)
