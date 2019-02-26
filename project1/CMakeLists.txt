
include_directories(${CMAKE_SOURCE_DIR}/libs/include)
set( SOURCE
        AES_CBC_PKCS7_SHA512.hpp
        AES_CBC_PKCS7_SHA512.cpp
        ApplicationHelp.hpp
        CommandLineArgument.hpp
        CipherWrapper.hpp
        HexUtils.hpp
        Print.cpp
        Print.hpp )


add_executable(project1 main.cpp ${SOURCE})
target_link_libraries(project1 "-L${CMAKE_SOURCE_DIR}/libs/static -lmbedtls -lmbedx509 -lmbedcrypto -mwindows")

enable_testing()
add_executable(test_project
        test/test-main.cpp
        test/test-impl.cpp
        ${SOURCE}
        )
target_link_libraries(test_project "-L${CMAKE_SOURCE_DIR}/libs/static -lmbedtls -lmbedx509 -lmbedcrypto -mwindows")
add_test(test test_project COMMAND test_project1)

add_custom_target(
        run_test
        COMMAND ${CMAKE_COMMAND} -E echo_append "Running test..."
        COMMAND project1/test_project
        DEPENDS test_project
        COMMAND ${CMAKE_COMMAND} -E echo "Done."
        WORKING_DIRECTORY ${CMAKE_PROJECT_DIR}
        )




