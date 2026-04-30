cmake_minimum_required(VERSION 3.24)

project(gmssh_client VERSION 0.1.0 LANGUAGES CXX)

set(GMSSH_PRODUCT_NAME "CipherShell")
set(GMSSH_EXECUTABLE_NAME "CipherShell")
set(GMSSH_PACKAGE_BASENAME "ciphershell")
set(GMSSH_BUNDLE_IDENTIFIER "com.internal.ciphershell")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

option(GMSSH_BUILD_GUI "Build Qt GUI client" ON)
option(GMSSH_BUILD_TESTS "Build unit tests" ON)
option(GMSSH_ENABLE_QTERMWIDGET "Enable QTermWidget integration when available" ON)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

find_package(OpenSSL REQUIRED)
find_package(Qt6 REQUIRED COMPONENTS Core Network)

if(GMSSH_BUILD_GUI)
  find_package(Qt6 REQUIRED COMPONENTS Widgets)
endif()

if(GMSSH_ENABLE_QTERMWIDGET)
  find_package(QTermWidget QUIET)
endif()

add_library(gmssh_core
  src/core/types.cpp
  src/core/profile_repository.cpp
  src/core/audit_logger.cpp
  src/core/credential_store.cpp
  src/core/crypto_utils.cpp
  src/core/ssh_command_builder.cpp
  src/core/ssh_engine_adapter.cpp
)

target_include_directories(gmssh_core PUBLIC src)
target_link_libraries(gmssh_core
  PUBLIC Qt6::Core Qt6::Network
  PRIVATE OpenSSL::Crypto
)

if(QTermWidget_FOUND)
  target_compile_definitions(gmssh_core PUBLIC GMSSH_HAS_QTERMWIDGET=1)
endif()

if(GMSSH_BUILD_GUI)
  set(GMSSH_CLIENT_TARGET_OPTIONS)
  if(APPLE)
    list(APPEND GMSSH_CLIENT_TARGET_OPTIONS MACOSX_BUNDLE)
  elseif(WIN32)
    list(APPEND GMSSH_CLIENT_TARGET_OPTIONS WIN32)
  endif()

  add_executable(gmssh_client
    ${GMSSH_CLIENT_TARGET_OPTIONS}
    src/main.cpp
    src/gui/main_window.cpp
    src/gui/session_profile_dialog.cpp
    src/gui/profile_editor.cpp
    src/gui/forwarding_panel.cpp
    src/gui/terminal_session_widget.cpp
    src/gui/sftp_panel.cpp
    src/gui/audit_log_view.cpp
    resources/gmssh.qrc
  )

  if(APPLE)
    set(GMSSH_APP_ICON "${CMAKE_CURRENT_SOURCE_DIR}/resources/icons/gmssh.icns")
    if(EXISTS "${GMSSH_APP_ICON}")
      target_sources(gmssh_client PRIVATE "${GMSSH_APP_ICON}")
      set_source_files_properties("${GMSSH_APP_ICON}" PROPERTIES
        MACOSX_PACKAGE_LOCATION "Resources"
      )
    endif()
  elseif(WIN32)
    set(GMSSH_WINDOWS_ICON "${CMAKE_CURRENT_SOURCE_DIR}/resources/windows/gmssh.ico")
    set(GMSSH_WINDOWS_RC_IN "${CMAKE_CURRENT_SOURCE_DIR}/resources/windows/gmssh_client.rc.in")
    if(EXISTS "${GMSSH_WINDOWS_ICON}" AND EXISTS "${GMSSH_WINDOWS_RC_IN}")
      file(TO_CMAKE_PATH "${GMSSH_WINDOWS_ICON}" GMSSH_WINDOWS_ICON_RC)
      configure_file("${GMSSH_WINDOWS_RC_IN}" "${CMAKE_CURRENT_BINARY_DIR}/gmssh_client.rc" @ONLY)
      target_sources(gmssh_client PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/gmssh_client.rc")
    endif()
  endif()

  target_link_libraries(gmssh_client
    PRIVATE gmssh_core Qt6::Widgets
  )

  if(UNIX AND NOT APPLE)
    target_link_libraries(gmssh_client PRIVATE util)
  endif()

  if(QTermWidget_FOUND)
    target_link_libraries(gmssh_client PRIVATE QTermWidget::QTermWidget)
    target_compile_definitions(gmssh_client PRIVATE GMSSH_HAS_QTERMWIDGET=1)
  endif()

  set_target_properties(gmssh_client PROPERTIES
    OUTPUT_NAME "${GMSSH_EXECUTABLE_NAME}"
    MACOSX_BUNDLE_BUNDLE_NAME "${GMSSH_PRODUCT_NAME}"
    MACOSX_BUNDLE_GUI_IDENTIFIER "${GMSSH_BUNDLE_IDENTIFIER}"
    MACOSX_BUNDLE_BUNDLE_VERSION "${PROJECT_VERSION}"
    MACOSX_BUNDLE_ICON_FILE "gmssh.icns"
    MACOSX_BUNDLE_SHORT_VERSION_STRING "${PROJECT_VERSION}"
  )

  set(GMSSH_ENGINE_SUFFIX "")
  if(WIN32)
    set(GMSSH_ENGINE_SUFFIX ".exe")
  endif()

  set(GMSSH_ENGINE_SSH "${CMAKE_CURRENT_SOURCE_DIR}/bin/ssh${GMSSH_ENGINE_SUFFIX}")
  set(GMSSH_ENGINE_SFTP "${CMAKE_CURRENT_SOURCE_DIR}/bin/sftp${GMSSH_ENGINE_SUFFIX}")
  set(GMSSH_LEGACY_ENGINE_SSH "" CACHE FILEPATH "Optional legacy EC-GM SSH engine")
  set(GMSSH_LEGACY_ENGINE_SFTP "" CACHE FILEPATH "Optional legacy EC-GM SFTP engine")

  if(NOT GMSSH_LEGACY_ENGINE_SSH)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/bin/ssh-legacy-ecgm${GMSSH_ENGINE_SUFFIX}")
      set(GMSSH_LEGACY_ENGINE_SSH "${CMAKE_CURRENT_SOURCE_DIR}/bin/ssh-legacy-ecgm${GMSSH_ENGINE_SUFFIX}")
    elseif(EXISTS "${CMAKE_CURRENT_BINARY_DIR}/stage/bin/ssh${GMSSH_ENGINE_SUFFIX}")
      set(GMSSH_LEGACY_ENGINE_SSH "${CMAKE_CURRENT_BINARY_DIR}/stage/bin/ssh${GMSSH_ENGINE_SUFFIX}")
    endif()
  endif()

  if(NOT GMSSH_LEGACY_ENGINE_SFTP)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/bin/sftp-legacy-ecgm${GMSSH_ENGINE_SUFFIX}")
      set(GMSSH_LEGACY_ENGINE_SFTP "${CMAKE_CURRENT_SOURCE_DIR}/bin/sftp-legacy-ecgm${GMSSH_ENGINE_SUFFIX}")
    elseif(EXISTS "${CMAKE_CURRENT_BINARY_DIR}/stage/bin/sftp${GMSSH_ENGINE_SUFFIX}")
      set(GMSSH_LEGACY_ENGINE_SFTP "${CMAKE_CURRENT_BINARY_DIR}/stage/bin/sftp${GMSSH_ENGINE_SUFFIX}")
    endif()
  endif()

  if(EXISTS "${GMSSH_ENGINE_SSH}" AND EXISTS "${GMSSH_ENGINE_SFTP}")
    add_custom_command(TARGET gmssh_client POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:gmssh_client>/bin"
      COMMAND ${CMAKE_COMMAND} -E copy_if_different "${GMSSH_ENGINE_SSH}" "$<TARGET_FILE_DIR:gmssh_client>/bin/ssh${GMSSH_ENGINE_SUFFIX}"
      COMMAND ${CMAKE_COMMAND} -E copy_if_different "${GMSSH_ENGINE_SFTP}" "$<TARGET_FILE_DIR:gmssh_client>/bin/sftp${GMSSH_ENGINE_SUFFIX}"
      VERBATIM
    )
    if(NOT APPLE)
      install(PROGRAMS "${GMSSH_ENGINE_SSH}" "${GMSSH_ENGINE_SFTP}" DESTINATION bin)
    endif()
  else()
    message(WARNING "Bundled SSH engine binaries not found in ${CMAKE_CURRENT_SOURCE_DIR}/bin; GUI may fall back to system ssh/sftp.")
  endif()

  if(EXISTS "${GMSSH_LEGACY_ENGINE_SSH}" AND EXISTS "${GMSSH_LEGACY_ENGINE_SFTP}")
    add_custom_command(TARGET gmssh_client POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:gmssh_client>/bin"
      COMMAND ${CMAKE_COMMAND} -E copy_if_different "${GMSSH_LEGACY_ENGINE_SSH}" "$<TARGET_FILE_DIR:gmssh_client>/bin/ssh-legacy-ecgm${GMSSH_ENGINE_SUFFIX}"
      COMMAND ${CMAKE_COMMAND} -E copy_if_different "${GMSSH_LEGACY_ENGINE_SFTP}" "$<TARGET_FILE_DIR:gmssh_client>/bin/sftp-legacy-ecgm${GMSSH_ENGINE_SUFFIX}"
      VERBATIM
    )
    if(NOT APPLE)
      install(PROGRAMS "${GMSSH_LEGACY_ENGINE_SSH}" DESTINATION bin RENAME "ssh-legacy-ecgm${GMSSH_ENGINE_SUFFIX}")
      install(PROGRAMS "${GMSSH_LEGACY_ENGINE_SFTP}" DESTINATION bin RENAME "sftp-legacy-ecgm${GMSSH_ENGINE_SUFFIX}")
    endif()
  else()
    message(WARNING "Legacy EC-GM engine binaries not found; Kylin ecgm compatibility fallback will be unavailable in packaged builds.")
  endif()

  install(TARGETS gmssh_client BUNDLE DESTINATION . RUNTIME DESTINATION bin)
endif()

add_custom_target(gmssh_engine
  COMMAND ${CMAKE_COMMAND} -E echo "Use scripts/build_openssh_engine.sh to build bundled OpenSSH GM engine"
  VERBATIM
)

if(GMSSH_BUILD_TESTS)
  enable_testing()
  add_executable(gmssh_core_tests tests/test_core.cpp)
  target_link_libraries(gmssh_core_tests PRIVATE gmssh_core)
  add_test(NAME gmssh_core_tests COMMAND gmssh_core_tests)

  if(GMSSH_BUILD_GUI)
    add_executable(gmssh_gui_tests
      tests/test_sftp_panel.cpp
      src/gui/main_window.cpp
      src/gui/session_profile_dialog.cpp
      src/gui/profile_editor.cpp
      src/gui/forwarding_panel.cpp
      src/gui/terminal_session_widget.cpp
      src/gui/sftp_panel.cpp
      src/gui/audit_log_view.cpp
      resources/gmssh.qrc
    )
    target_link_libraries(gmssh_gui_tests PRIVATE gmssh_core Qt6::Widgets)
    if(UNIX AND NOT APPLE)
      target_link_libraries(gmssh_gui_tests PRIVATE util)
    endif()
    add_test(NAME gmssh_gui_tests COMMAND gmssh_gui_tests)
    set_tests_properties(gmssh_gui_tests PROPERTIES
      ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
    )
  endif()

  add_executable(gmssh_p1_matrix tests/p1_matrix.cpp)
  target_link_libraries(gmssh_p1_matrix PRIVATE gmssh_core)
endif()

set(CPACK_PACKAGE_NAME "${GMSSH_PRODUCT_NAME}")
set(CPACK_PACKAGE_VENDOR "internal")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_FILE_NAME "${GMSSH_PACKAGE_BASENAME}-${PROJECT_VERSION}-${CMAKE_SYSTEM_NAME}")

if(APPLE)
  set(CPACK_GENERATOR "DragNDrop")
elseif(WIN32)
  set(CPACK_GENERATOR "NSIS")
else()
  set(CPACK_GENERATOR "TGZ")
endif()

include(CPack)
