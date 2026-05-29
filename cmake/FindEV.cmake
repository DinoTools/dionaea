# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2018 PhiBo (DinoTools)
#
# SPDX-License-Identifier: GPL-2.0-or-later

find_path(EV_INCLUDE_DIR ev.h)
find_library(EV_LIBRARY NAMES ev)

if(EV_INCLUDE_DIR)
    if(EXISTS "${EV_INCLUDE_DIR}/ev.h")
        file(STRINGS "${EV_INCLUDE_DIR}/ev.h" ev_version_major_str REGEX "^#define[\t ]+EV_VERSION_MAJOR[\t ]+.*")
        file(STRINGS "${EV_INCLUDE_DIR}/ev.h" ev_version_minor_str REGEX "^#define[\t ]+EV_VERSION_MINOR[\t ]+.*")

        string(REGEX REPLACE "^#define[\t ]+EV_VERSION_MAJOR[\t ]+([0-9]+).*" "\\1" EV_VERSION_MAJOR_STRING "${ev_version_major_str}")
        string(REGEX REPLACE "^#define[\t ]+EV_VERSION_MINOR[\t ]+([0-9]+).*" "\\1" EV_VERSION_MINOR_STRING "${ev_version_minor_str}")
        set(EV_VERSION_STRING "${EV_VERSION_MAJOR_STRING}.${EV_VERSION_MINOR_STRING}")
        unset(ev_version_major_str)
        unset(ev_version_minor_str)
    endif()
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(
    EV
    REQUIRED_VARS
        EV_LIBRARY
        EV_INCLUDE_DIR
    VERSION_VAR
        EV_VERSION_STRING
)

if(EV_FOUND)
    set(EV_LIBRARIES ${EV_LIBRARY})
    set(EV_INCLUDE_DIRS ${EV_INCLUDE_DIR})

    if(NOT TARGET EV::EV)
        add_library(EV::EV UNKNOWN IMPORTED)
        set_target_properties(
            EV::EV
            PROPERTIES
            IMPORTED_LINK_INTERFACE_LANGUAGES "C"
            IMPORTED_LOCATION "${EV_LIBRARIES}"
            INTERFACE_INCLUDE_DIRECTORIES "${EV_INCLUDE_DIRS}"
        )
    endif()
endif()
