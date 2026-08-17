if(NOT DEFINED PBNS_CN_CBOR_SOURCE OR NOT DEFINED PBNS_CN_CBOR_DESTINATION OR
   NOT DEFINED PBNS_CN_CBOR_PATCH)
    message(FATAL_ERROR "Incomplete cn-cbor source preparation arguments")
endif()

file(REMOVE_RECURSE "${PBNS_CN_CBOR_DESTINATION}")
file(MAKE_DIRECTORY "${PBNS_CN_CBOR_DESTINATION}")
file(COPY "${PBNS_CN_CBOR_SOURCE}/" DESTINATION "${PBNS_CN_CBOR_DESTINATION}")
file(REMOVE_RECURSE "${PBNS_CN_CBOR_DESTINATION}/.git")

execute_process(
    COMMAND patch --batch --forward -p1 --input "${PBNS_CN_CBOR_PATCH}"
    WORKING_DIRECTORY "${PBNS_CN_CBOR_DESTINATION}"
    RESULT_VARIABLE patch_status
    OUTPUT_VARIABLE patch_output
    ERROR_VARIABLE patch_error
)
if(NOT patch_status EQUAL 0)
    message(FATAL_ERROR "cn-cbor compatibility patch failed:\n${patch_output}${patch_error}")
endif()
