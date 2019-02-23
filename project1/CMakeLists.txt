
include_directories(${CMAKE_SOURCE_DIR}/libs/include)
add_executable(project1
        main.cpp
        ApplicationHelp.hpp
        CommandLineArgument.hpp
        Print.cpp
        Print.hpp
        )

target_link_libraries(project1 "-L${CMAKE_SOURCE_DIR}/libs/static -lmbedtls -lmbedx509 -lmbedcrypto -mwindows")



