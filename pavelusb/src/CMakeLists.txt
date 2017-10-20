cmake_minimum_required(VERSION 2.8)
project(pavelusb)

if(WIN32)
    message("Building against hid")
    set(SOURCES hiddata_mswin.c)
    set(LIBRARIES hid setupapi)
elseif(${CMAKE_SYSTEM_NAME} STREQUAL Darwin AND NOT USE_LIBUSB_ON_MACOS)
    option(USE_LIBUSB_ON_MACOS "Use libusb instead of IOKit on MacOS" ON)

    set(SOURCES hiddata_osx.c)
    set(LIBRARIES
        "-framework CoreFoundation"
        "-framework IOKit"
    )
else()
    set(SOURCES hiddata_libusb01.c)
    include(FindPkgConfig)
    pkg_check_modules(LIBUSB REQUIRED libusb)
    include_directories(${LIBUSB_INCLUDE_DIRS})
    set(LIBRARIES ${LIBUSB_LIBRARIES})
endif()

add_library(hidusb-relay SHARED ${SOURCES})
target_link_libraries(hidusb-relay ${LIBRARIES})

add_executable(pavelusb usbrelay-cmd.c)
target_link_libraries(pavelusb hidusb-relay)
