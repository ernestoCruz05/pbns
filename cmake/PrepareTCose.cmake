if(NOT DEFINED PBNS_T_COSE_SOURCE OR NOT DEFINED PBNS_T_COSE_DESTINATION OR
   NOT DEFINED PBNS_T_COSE_PATCHES)
    message(FATAL_ERROR "Incomplete t_cose source preparation arguments")
endif()

file(REMOVE_RECURSE "${PBNS_T_COSE_DESTINATION}")
file(MAKE_DIRECTORY "${PBNS_T_COSE_DESTINATION}")
file(COPY "${PBNS_T_COSE_SOURCE}/" DESTINATION "${PBNS_T_COSE_DESTINATION}")
file(REMOVE_RECURSE "${PBNS_T_COSE_DESTINATION}/.git")

foreach(patch_path IN LISTS PBNS_T_COSE_PATCHES)
    execute_process(
        COMMAND patch --batch --forward -p1 --input "${patch_path}"
        WORKING_DIRECTORY "${PBNS_T_COSE_DESTINATION}"
        RESULT_VARIABLE patch_status
        OUTPUT_VARIABLE patch_output
        ERROR_VARIABLE patch_error
    )
    if(NOT patch_status EQUAL 0)
        message(FATAL_ERROR
            "t_cose compatibility patch failed (${patch_path}):\n${patch_output}${patch_error}")
    endif()
endforeach()
