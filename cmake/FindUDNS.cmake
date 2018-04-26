find_path(UDNS_INCLUDE_DIR udns.h)
find_library(UDNS_LIBRARY NAMES udns)

if(UDNS_INCLUDE_DIR)
    if(EXISTS "${UDNS_INCLUDE_DIR}/udns.h")
        file(STRINGS "${UDNS_INCLUDE_DIR}/udns.h" udns_version_str REGEX "^#define[\t ]+UDNS_VERSION[\t ]+\".*\"")

        string(REGEX REPLACE "^#define[\t ]+UDNS_VERSION[\t ]+\"([^\"]*)\".*" "\\1" UDNS_VERSION_STRING "${udns_version_str}")
        unset(udns_version_str)
    endif()
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(
    UDNS
    REQUIRED_VARS
    UDNS_LIBRARY
    UDNS_INCLUDE_DIR
    VERSION_VAR
    UDNS_VERSION_STRING
)

if(UDNS_FOUND)
    set(UDNS_LIBRARIES ${UDNS_LIBRARY})
    set(UDNS_INCLUDE_DIRS ${UDNS_INCLUDE_DIR})

    if(NOT TARGET UDNS::UDNS)
        add_library(UDNS::UDNS UNKNOWN IMPORTED)
        set_target_properties(
            UDNS::UDNS
            PROPERTIES
            IMPORTED_LINK_INTERFACE_LANGUAGES "C"
            IMPORTED_LOCATION "${UDNS_LIBRARIES}"
            INTERFACE_INCLUDE_DIRECTORIES "${UDNS_INCLUDE_DIRS}"
        )
    endif()
endif()
