CMAKE_MINIMUM_REQUIRED(VERSION 2.6)

SET (this_target privileges)

SET(LIBRARY_OUTPUT_PATH ${CMAKE_SOURCE_DIR}/cmake_build_tmp/output)

INCLUDE(FindPkgConfig)
pkg_check_modules(pkg REQUIRED glib-2.0 dlog libxml-2.0)

FOREACH(flag ${privileges_CFLAGS})
    SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

INCLUDE_DIRECTORIES(
    /usr/include
    /usr/include/glib-2.0
    /usr/include/libxml2
    /usr/include/package_manager
    /usr/include/dlog
    "${CMAKE_SOURCE_DIR}/client/inc/"
    "${CMAKE_SOURCE_DIR}/common/inc/"
    "${CMAKE_SOURCE_DIR}/include/"
    )

SET (${this_target}_SOURCE_FILES
    privileges.cpp
    )

ADD_DEFINITIONS("-DDLOG_ERROR_ENABLED")
ADD_DEFINITIONS("-DLOG_TAG=\"PRIVILEGE_PLUGIN\"")
SET(EXTRA_CFLAGS  "${EXTRA_CFLAGS} -Wall" )

SET(CMAKE_C_FLAGS_PROFILING    " -g -pg")
SET(CMAKE_CXX_FLAGS_PROFILING  " -std=c++0x -g -pg")
SET(CMAKE_C_FLAGS_DEBUG        " -g")
SET(CMAKE_CXX_FLAGS_DEBUG      " -std=c++0x -g")
SET(CMAKE_C_FLAGS_RELEASE      " -g")
SET(CMAKE_CXX_FLAGS_RELEASE    " -std=c++0x -g")
SET(CMAKE_C_FLAGS_CCOV         " -g --coverage")
SET(CMAKE_CXX_FLAGS_CCOV       " -std=c++0x -g --coverage")

## Create Library
ADD_LIBRARY (${this_target} SHARED ${${this_target}_SOURCE_FILES} )
ADD_DEPENDENCIES(${this_target} privacy-guard-client)
## SET LINKER FLAGS
SET(CMAKE_SHARED_LINKER_FLAGS -Wl,--no-undefined)

TARGET_LINK_LIBRARIES(${this_target} ${pkg_LDFLAGS} ${pkg_LIBRARIES})
TARGET_LINK_LIBRARIES(${this_target} "-lprivacy-guard-client" "-L../client" )

ADD_CUSTOM_COMMAND(TARGET ${this_target}
    POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy ${LIBRARY_OUTPUT_PATH}/${CMAKE_SHARED_LIBRARY_PREFIX}${this_target}${CMAKE_SHARED_LIBRARY_SUFFIX} ${LIBRARY_OUTPUT_PATH}/debug/${CMAKE_SHARED_LIBRARY_PREFIX}${this_target}${CMAKE_SHARED_LIBRARY_SUFFIX}
        COMMAND ${CMAKE_STRIP} --strip-unneeded ${LIBRARY_OUTPUT_PATH}/${CMAKE_SHARED_LIBRARY_PREFIX}${this_target}${CMAKE_SHARED_LIBRARY_SUFFIX}
    COMMENT "strip ${this_target}"
        )

INSTALL(TARGETS ${this_target} DESTINATION ${SYSCONF_INSTALL_DIR}/package-manager/parserlib/)

