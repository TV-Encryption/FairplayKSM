cmake_minimum_required(VERSION 3.12)

# set the project name
project(FairplayKSM)

INCLUDE_DIRECTORIES(include)

## Deps
find_package(Python 3.8 REQUIRED COMPONENTS Development Interpreter)
include_directories(${Python_INCLUDE_DIRS})

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

## Export library
# add the executable
Python_add_library(FairplayKSM MODULE
    FairplayKSM
    source/SKDServer
    source/SKDServerUtils
#    source/DFunction
    source/SKDStubDFunction
    )

## Linking
target_link_libraries(FairplayKSM PRIVATE ${OPENSSL_LIBRARIES})

## Export headers
# Make sure the compiler can find include files for our Hello library
# when other libraries or executables link to Hello
target_include_directories(FairplayKSM PUBLIC "${PROJECT_BINARY_DIR}")

## Install config
install(TARGETS FairplayKSM DESTINATION ${Python_SITELIB}) ## Should preferably be /usr/local/lib/python3.8/dist-packages
install(FILES FairplayKSM.pyi DESTINATION ${Python_SITELIB})