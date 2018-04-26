function(install_available_python_config)
    set(options)
    set(oneValueArgs SOURCE_DIR BUILD_DIR DESTINATION_DIR)
    set(multiValueArgs FILES)
    cmake_parse_arguments(MY_FUNC "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN} )

    foreach(_filename ${MY_FUNC_FILES})
        if(_filename MATCHES ".in$")
            string(REGEX REPLACE "\\.in$" "" _new_filename ${_filename})
            file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/conf/${MY_FUNC_BUILD_DIR}")
            configure_file(
                "${PROJECT_SOURCE_DIR}/conf/${MY_FUNC_SOURCE_DIR}/${_filename}"
                "${CMAKE_CURRENT_BINARY_DIR}/conf/${MY_FUNC_BUILD_DIR}/${_new_filename}"
                @ONLY
            )
            install_if_not_exists(
                "${CMAKE_CURRENT_BINARY_DIR}/conf/${MY_FUNC_BUILD_DIR}/${_new_filename}"
		"${CMAKE_INSTALL_FULL_SYSCONFDIR}/dionaea/${MY_FUNC_DESTINATION_DIR}"
            )
        else()
            install_if_not_exists(
                "${PROJECT_SOURCE_DIR}/conf/${MY_FUNC_SOURCE_DIR}/${_filename}"
		"${CMAKE_INSTALL_FULL_SYSCONFDIR}/dionaea/${MY_FUNC_DESTINATION_DIR}"
            )
        endif()
    endforeach()
endfunction()

function(install_enabled_python_config)
    set(options)
    set(oneValueArgs DESTINATION SOURCE_REL_DIR)
    set(multiValueArgs FILES)
    cmake_parse_arguments(MY_FUNC "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN} )

    if(CMAKE_HOST_UNIX)
        set(_conf_dst "${CMAKE_INSTALL_FULL_SYSCONFDIR}/dionaea/${MY_FUNC_DESTINATION}")
        if(NOT EXISTS "${_conf_dst}")
            install(DIRECTORY DESTINATION "${_conf_dst}")
            foreach(filename ${MY_FUNC_FILES})
                install(CODE "message(STATUS \"Enabling Service: ${filename} in ${_conf_dst}\")")
                install(CODE "
                EXECUTE_PROCESS(
                    COMMAND \"${CMAKE_COMMAND}\" -E create_symlink
                        ${MY_FUNC_SOURCE_REL_DIR}/${filename}
                        ${filename}
                    WORKING_DIRECTORY \"${_conf_dst}\"
                )
            ")
            endforeach()
        endif()
    endif()
endfunction()
