include(ExternalProject)

set(CMAKE_ARGS
  -DCMAKE_POLICY_DEFAULT_CMP0091:STRING=NEW 
  -DCMAKE_MSVC_RUNTIME_LIBRARY:STRING=MultiThreaded$<$<CONFIG:Debug>:Debug>
  -DFMT_TEST:BOOLEAN=OFF
  -DFMT_DOC:BOOLEAN=OFF)

ExternalProject_Add(
  fmt_project
  GIT_REPOSITORY    https://github.com/fmtlib/fmt.git
  GIT_TAG           master
  GIT_SHALLOW       1
  PREFIX            ${PROJECT_SOURCE_DIR}/extern/fmt
  DOWNLOAD_DIR      ${PROJECT_SOURCE_DIR}/extern/fmt
  SOURCE_DIR        ${PROJECT_SOURCE_DIR}/extern/fmt/source
  BINARY_DIR        ${PROJECT_SOURCE_DIR}/extern/fmt/build
  CMAKE_ARGS        ${CMAKE_ARGS}
  INSTALL_COMMAND   ""
  TEST_COMMAND      ""
)

ExternalProject_Get_Property(fmt_project source_dir)
ExternalProject_Get_Property(fmt_project binary_dir)
set(FMT_HEADERS ${source_dir}/include)
set(FMT_LIBS ${binary_dir})

