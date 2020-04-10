enable_language(CXX)

set(CMAKE_CXX_STANDARD 11)

include(${PROJECT_SOURCE_DIR}/extern/cmake/fmt.cmake)
include(${PROJECT_SOURCE_DIR}/extern/cmake/libtommath.cmake)
include(${PROJECT_SOURCE_DIR}/extern/cmake/libtomcrypt.cmake)

set(SOURCES dllmain.cpp libpakdecrypt.cpp TomCryption.cpp ZipUtil.cpp)
set(HEADERS libpakdecrypt.h TomCryption.h ZipUtil.h errors.h dll.h)

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_library(libcrypak SHARED ${SOURCES} ${HEADERS})

target_compile_definitions(libcrypak PUBLIC -DBUILD_DLL -DLTM_DESC)

set_property(TARGET libcrypak PROPERTY
  MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_dependencies(libtomcrypt_project libtommath_project)
add_dependencies(libcrypak fmt_project libtommath_project libtomcrypt_project)

target_include_directories(libcrypak PUBLIC
                           "${PROJECT_SOURCE_DIR}/extern/fmt/include"
                           "${FMT_HEADERS}"
                           "${LIBTOMCRYPT_HEADERS}"
)

target_link_directories(libcrypak PUBLIC
                        "${FMT_LIBS}"
                        "${LIBTOMMATH_LIBS}"
                        "${LIBTOMCRYPT_LIBS}"
)

target_link_libraries(libcrypak fmt.lib tommath.lib tomcrypt.lib)

install(TARGETS libcrypak
        RUNTIME DESTINATION ${CMAKE_SOURCE_DIR}/dist
        ARCHIVE DESTINATION ${CMAKE_SOURCE_DIR}/dist
        LIBRARY DESTINATION ${CMAKE_SOURCE_DIR}/dist
)

