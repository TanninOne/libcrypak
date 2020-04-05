include(ExternalProject)

if (WIN32)
  set(MAKE nmake)
  set(MAKEFILE makefile.msvc)
else (WIN32)
  set(MAKE make)
  set(MAKEFILE makefile)
endif (WIN32)

ExternalProject_Add(
  libtommath_project
  GIT_REPOSITORY    https://github.com/libtom/libtommath.git
  GIT_TAG           master
  GIT_SHALLOW       1
  DOWNLOAD_DIR      ${PROJECT_SOURCE_DIR}/extern/libtommath
  SOURCE_DIR        "${PROJECT_SOURCE_DIR}/extern/libtommath"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND     ${MAKE} /f ${MAKEFILE}
  BUILD_IN_SOURCE   1
  INSTALL_COMMAND   ""
)

ExternalProject_Get_Property(libtommath_project source_dir)
set(LIBTOMMATH_HEADERS ${source_dir})
set(LIBTOMMATH_LIBS ${source_dir})

