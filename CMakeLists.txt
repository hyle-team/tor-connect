cmake_minimum_required (VERSION 3.8)

project("tor-connect")

SET(Boost_USE_STATIC_LIBS ON)           # link statically


if(MSVC)
  add_definitions("/D_CRT_SECURE_NO_WARNINGS /D_WIN32_WINNT=0x0600 /DWIN32_LEAN_AND_MEAN")
endif()


add_definitions("/DHTTP_ENABLE_GZIP")


file(GLOB_RECURSE TOR_LIB_FILES torlib/*.cpp torlib/*.h)    

add_library(tor-connect "tor-connect.cpp" "tor-connect.h" ${TOR_LIB_FILES} )

#target_compile_features(${PROJECT_NAME} PRIVATE cxx_std_17)

message("CMAKE_SYSTEM_NAME: ${CMAKE_SYSTEM_NAME}")
if(CMAKE_SYSTEM_NAME STREQUAL "Android")
  find_package(Boost 1.71 REQUIRED COMPONENTS regex log)
  set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -fPIC")
  set(CMAKE_C_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -fPIC")
elseif(APPLE)
  find_package(Boost 1.71 REQUIRED COMPONENTS regex log)
else()
  find_package(Boost 1.70 REQUIRED COMPONENTS regex log)
endif()

target_include_directories(${PROJECT_NAME} PUBLIC ${Boost_INCLUDE_DIRS}) 
target_link_libraries(${PROJECT_NAME} ${Boost_LIBRARIES})

set(OPENSSL_USE_STATIC_LIBS TRUE) # link statically
target_include_directories(${PROJECT_NAME} PUBLIC ${OPENSSL_INCLUDE_DIR})
target_link_libraries(${PROJECT_NAME} OpenSSL::SSL OpenSSL::Crypto)
if(WIN32)
  target_link_libraries(${PROJECT_NAME} Crypt32)
endif()

message(STATUS "SSL INCLUDE DIRS: ${OPENSSL_INCLUDE_DIR}")
