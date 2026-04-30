include(FindPackageHandleStandardArgs)
find_package(PkgConfig QUIET)

if(PkgConfig_FOUND)
  pkg_check_modules(PC_QTERM QUIET qtermwidget6 qtermwidget5 qtermwidget)
endif()

find_path(QTermWidget_INCLUDE_DIR
  NAMES qtermwidget.h
  HINTS ${PC_QTERM_INCLUDE_DIRS}
  PATH_SUFFIXES qtermwidget6 qtermwidget5
)

find_library(QTermWidget_LIBRARY
  NAMES qtermwidget6 qtermwidget5 qtermwidget
  HINTS ${PC_QTERM_LIBRARY_DIRS}
)

find_package_handle_standard_args(QTermWidget
  REQUIRED_VARS QTermWidget_INCLUDE_DIR QTermWidget_LIBRARY
)

if(QTermWidget_FOUND AND NOT TARGET QTermWidget::QTermWidget)
  add_library(QTermWidget::QTermWidget UNKNOWN IMPORTED)
  set_target_properties(QTermWidget::QTermWidget PROPERTIES
    IMPORTED_LOCATION "${QTermWidget_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${QTermWidget_INCLUDE_DIR}"
  )
endif()
