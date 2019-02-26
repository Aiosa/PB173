
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

add_executable(test_p1
        test/test-main.cpp
        test/test-impl.cpp
        ${SOURCE}
        )
target_link_libraries(test_p1 "-L${CMAKE_SOURCE_DIR}/libs/static -lmbedtls -lmbedx509 -lmbedcrypto -mwindows")
add_test(test_p1_run test_p1)

