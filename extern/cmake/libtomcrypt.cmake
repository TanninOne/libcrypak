include(ExternalProject)

if (WIN32)
  set(MAKE nmake)
  set(MAKEFILE makefile.msvc)
else (WIN32)
  set(MAKE make)
  set(MAKEFILE makefile)
endif (WIN32)

set(BUILD_FLAGS "-DUSE_LTM")
set(BUILD_FLAGS "${BUILD_FLAGS} -DLTM_DESC")
set(BUILD_FLAGS "${BUILD_FLAGS} -I../libtommath")

ExternalProject_Add(
  libtomcrypt_project
  GIT_REPOSITORY    https://github.com/libtom/libtomcrypt.git
  GIT_TAG           master
  GIT_SHALLOW       1
  DOWNLOAD_DIR      ${PROJECT_SOURCE_DIR}/extern/libtomcrypt
  SOURCE_DIR        ${PROJECT_SOURCE_DIR}/extern/libtomcrypt
  CONFIGURE_COMMAND ""
  BUILD_COMMAND     ${MAKE} -f ${MAKEFILE} "CFLAGS=${BUILD_FLAGS}"
  BUILD_IN_SOURCE   1
  INSTALL_COMMAND   ""
)

ExternalProject_Get_Property(libtomcrypt_project source_dir)
set(LIBTOMCRYPT_HEADERS ${source_dir}/src/headers)
set(LIBTOMCRYPT_LIBS ${source_dir})

