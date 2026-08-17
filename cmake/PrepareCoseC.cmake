if(NOT DEFINED PBNS_COSE_SOURCE OR NOT DEFINED PBNS_COSE_DESTINATION OR
   NOT DEFINED PBNS_COSE_PATCH1 OR NOT DEFINED PBNS_COSE_PATCH2 OR
   NOT DEFINED PBNS_COSE_PATCH3 OR NOT DEFINED PBNS_COSE_PATCH4 OR
   NOT DEFINED PBNS_COSE_EXAMPLES)
    message(FATAL_ERROR "Incomplete COSE-C source preparation arguments")
endif()

file(REMOVE_RECURSE "${PBNS_COSE_DESTINATION}")
file(MAKE_DIRECTORY "${PBNS_COSE_DESTINATION}")
file(COPY "${PBNS_COSE_SOURCE}/" DESTINATION "${PBNS_COSE_DESTINATION}")
file(REMOVE_RECURSE "${PBNS_COSE_DESTINATION}/.git")
file(COPY "${PBNS_COSE_EXAMPLES}/"
     DESTINATION "${PBNS_COSE_DESTINATION}/Examples")

foreach(patch_file IN ITEMS
        "${PBNS_COSE_PATCH1}"
        "${PBNS_COSE_PATCH2}"
        "${PBNS_COSE_PATCH3}"
        "${PBNS_COSE_PATCH4}")
    execute_process(
        COMMAND patch --batch --forward -p1 --input "${patch_file}"
        WORKING_DIRECTORY "${PBNS_COSE_DESTINATION}"
        RESULT_VARIABLE patch_status
        OUTPUT_VARIABLE patch_output
        ERROR_VARIABLE patch_error
    )
    if(NOT patch_status EQUAL 0)
        message(FATAL_ERROR "COSE-C compatibility patch failed:\n${patch_output}${patch_error}")
    endif()
endforeach()
