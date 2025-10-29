set(eapp1_bin enclave1)
set(eapp1_src eapp1/enclave1.c)
set(eapp2_bin enclave2)
set(eapp2_src eapp2/enclave2.c)
set(host_bin zkid-acl-runner)
set(host_src host/host.cpp)
set(package_name "zkid-acl.ke")
set(package_script "./zkid-acl-runner enclave1 enclave2 eyrie-rt loader.bin")
set(eyrie_plugins "io_syscall linux_syscall env_setup")

# Build Rust ZK library (ark-groth16)
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/zklib/libzklib.a
    COMMAND cd ${CMAKE_CURRENT_SOURCE_DIR}/zklib && ./build-zklib.sh
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/zklib/src/lib.rs
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/zklib
    COMMENT "Building Rust ZK library (ark-groth16) for RISC-V"
)

add_custom_target(zklib ALL DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/zklib/libzklib.a)

# eapp1 (prover enclave) - no ZK library linked
add_executable(${eapp1_bin} ${eapp1_src})
target_include_directories(${eapp1_bin} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(${eapp1_bin} 
    ${KEYSTONE_LIB_EAPP}
    ${CMAKE_CURRENT_SOURCE_DIR}/zklib/libzklib.a
    ${KEYSTONE_LIB_EDGE}
    "-static"
    "-lpthread"
    "-ldl"
    "-lm"
    "-Wl,--allow-multiple-definition"
)
add_dependencies(${eapp1_bin} zklib)

# eapp2 (verifier enclave with ACL) - no ZK library linked
add_executable(${eapp2_bin} ${eapp2_src})
target_include_directories(${eapp2_bin} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(${eapp2_bin} 
    ${KEYSTONE_LIB_EAPP}
    ${CMAKE_CURRENT_SOURCE_DIR}/zklib/libzklib.a
    ${KEYSTONE_LIB_EDGE}
    "-static"
    "-lpthread"
    "-ldl"
    "-lm"
    "-Wl,--allow-multiple-definition"
)
add_dependencies(${eapp2_bin} zklib)

# host application - ZK library linked here
add_executable(${host_bin} ${host_src})
target_include_directories(${host_bin} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(${host_bin} 
    ${KEYSTONE_LIB_HOST} 
    ${KEYSTONE_LIB_EDGE}
    ${KEYSTONE_LIB_VERIFIER}
    "-lpthread"
)
add_dependencies(${host_bin} zklib)


# add target for shared Eyrie runtime (used by both enclaves)
set(eyrie_files_to_copy .options_log eyrie-rt loader.bin)
add_eyrie_runtime(zkid-acl-eyrie
        ${eyrie_plugins}
        ${eyrie_files_to_copy})

# add target for packaging
add_keystone_package(zkid-acl-package
        ${package_name}
        ${package_script}
        ${eyrie_files_to_copy} ${eapp1_bin} ${eapp2_bin} ${host_bin})

add_dependencies(zkid-acl-package zkid-acl-eyrie)

# add package to the top-level target
add_dependencies(examples zkid-acl-package)

