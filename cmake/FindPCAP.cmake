find_path(PCAP_INCLUDE_DIR pcap/pcap.h)
find_library(PCAP_LIBRARY NAMES pcap)

if(PCAP_INCLUDE_DIR)
    if(EXISTS "${PCAP_INCLUDE_DIR}/pcap/pcap.h")
        file(STRINGS "${PCAP_INCLUDE_DIR}/pcap/pcap.h" pcap_version_major_str REGEX "^#define[\t ]+PCAP_VERSION_MAJOR[\t ]+.*")
        file(STRINGS "${PCAP_INCLUDE_DIR}/pcap/pcap.h" pcap_version_minor_str REGEX "^#define[\t ]+PCAP_VERSION_MINOR[\t ]+.*")

        string(REGEX REPLACE "^#define[\t ]+PCAP_VERSION_MAJOR[\t ]+([0-9]+).*" "\\1" PCAP_VERSION_MAJOR_STRING "${pcap_version_major_str}")
        string(REGEX REPLACE "^#define[\t ]+PCAP_VERSION_MINOR[\t ]+([0-9]+).*" "\\1" PCAP_VERSION_MINOR_STRING "${pcap_version_minor_str}")
        set(PCAP_VERSION_STRING "${PCAP_VERSION_MAJOR_STRING}.${PCAP_VERSION_MINOR_STRING}")
        unset(pcap_version_major_str)
        unset(pcap_version_minor_str)
    endif()
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(
    PCAP
    REQUIRED_VARS
    PCAP_LIBRARY
    PCAP_INCLUDE_DIR
    VERSION_VAR
    PCAP_VERSION_STRING
)

if(PCAP_FOUND)
    set(PCAP_LIBRARIES ${PCAP_LIBRARY})
    set(PCAP_INCLUDE_DIRS ${PCAP_INCLUDE_DIR})

    if(NOT TARGET PCAP::PCAP)
        add_library(PCAP::PCAP UNKNOWN IMPORTED)
        set_target_properties(
            PCAP::PCAP
            PROPERTIES
            IMPORTED_LINK_INTERFACE_LANGUAGES "C"
            IMPORTED_LOCATION "${PCAP_LIBRARIES}"
            INTERFACE_INCLUDE_DIRECTORIES "${PCAP_INCLUDE_DIRS}"
        )
    endif()
endif()
