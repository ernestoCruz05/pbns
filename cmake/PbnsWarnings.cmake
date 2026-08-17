function(pbns_target_reproducible_debug target)
    target_compile_options(${target} PRIVATE
        "-ffile-prefix-map=${CMAKE_BINARY_DIR}=."
        "-fdebug-prefix-map=${CMAKE_BINARY_DIR}=."
        "-fmacro-prefix-map=${CMAKE_BINARY_DIR}=."
    )
endfunction()

function(pbns_target_sanitizer_link target)
    if(PBNS_SANITIZE STREQUAL "address,undefined")
        target_link_options(${target} PRIVATE
            -fsanitize=address,undefined
            -fno-sanitize-recover=all
            -fno-omit-frame-pointer
        )
    elseif(PBNS_SANITIZE STREQUAL "thread")
        target_link_options(${target} PRIVATE
            -fsanitize=thread
            -fno-omit-frame-pointer
        )
    elseif(NOT PBNS_SANITIZE STREQUAL "")
        message(FATAL_ERROR "Unsupported PBNS_SANITIZE value: ${PBNS_SANITIZE}")
    endif()
endfunction()

function(pbns_target_sanitizers target)
    if(PBNS_SANITIZE STREQUAL "address,undefined")
        target_compile_options(${target} PRIVATE
            -fsanitize=address,undefined
            -fno-sanitize-recover=all
            -fno-omit-frame-pointer
        )
    elseif(PBNS_SANITIZE STREQUAL "thread")
        target_compile_options(${target} PRIVATE
            -fsanitize=thread
            -fno-omit-frame-pointer
        )
    endif()
    pbns_target_sanitizer_link(${target})
endfunction()

function(pbns_target_cxx_warnings target)
    target_compile_features(${target} PRIVATE cxx_std_17)
    target_compile_options(${target} PRIVATE
        -g
        -Og
        -Wall
        -Wextra
        -Wpedantic
        -Wconversion
        -Wsign-conversion
        -Wshadow
        -Wvla
        -Wcast-qual
        -Wpointer-arith
        -Wdouble-promotion
        -Wwrite-strings
    )

    if(PBNS_WERROR)
        target_compile_options(${target} PRIVATE -Werror)
    endif()

    pbns_target_reproducible_debug(${target})
    pbns_target_sanitizers(${target})
endfunction()

function(pbns_target_warnings target)
    target_compile_features(${target} PRIVATE c_std_17)
    target_compile_options(${target} PRIVATE
        -g
        -Og
        -Wall
        -Wextra
        -Wpedantic
        -Wconversion
        -Wsign-conversion
        -Wshadow
        -Wvla
        -Wcast-qual
        -Wpointer-arith
        -Wmissing-prototypes
        -Wstrict-prototypes
        -Wdouble-promotion
        -Wwrite-strings
    )

    if(PBNS_WERROR)
        target_compile_options(${target} PRIVATE -Werror)
    endif()

    pbns_target_reproducible_debug(${target})
    pbns_target_sanitizers(${target})
endfunction()
