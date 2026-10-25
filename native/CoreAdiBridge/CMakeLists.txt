cmake_minimum_required(VERSION 3.20)
project(CoreAdiBridge LANGUAGES CXX)

add_executable(CoreAdiBridge CoreAdiBridge.cpp AdiDispatch.cpp)
set_target_properties(CoreAdiBridge PROPERTIES
    WIN32_EXECUTABLE FALSE
    OUTPUT_NAME "CoreAdiBridge"
)

if(MSVC)
    target_compile_options(CoreAdiBridge PRIVATE /W4 /EHsc)
endif()

target_link_libraries(CoreAdiBridge PRIVATE shell32)

set_target_properties(CoreAdiBridge PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/out"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_SOURCE_DIR}/out"
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_SOURCE_DIR}/out"
)
