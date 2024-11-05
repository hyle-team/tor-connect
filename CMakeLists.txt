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
if(CMAKE_SYSTEM_NAME STREQUAL "iOS")
  set(CMAKE_OSX_DEPLOYMENT_TARGET 12.00)
  set(Boost_LIBRARIES "libboost.a")
  #workaround for new XCode 12 policy for builds(now it includes a slice for the "arm64" when builds for simulator)
  set(__iphoneos_archs "arm64")
  #set(__iphonesimulator_archs "arm64,x86_64")
  set(CMAKE_XCODE_ATTRIBUTE_ARCHS[sdk=iphoneos*] "${__iphoneos_archs}")
  set(CMAKE_XCODE_ATTRIBUTE_VALID_ARCHS[sdk=iphoneos*] "${__iphoneos_archs}")
  #set(CMAKE_XCODE_ATTRIBUTE_ARCHS[sdk=iphonesimulator*] "${__iphonesimulator_archs}")
  #set(CMAKE_XCODE_ATTRIBUTE_VALID_ARCHS[sdk=iphonesimulator*] "${__iphonesimulator_archs}")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Android")
  set(Boost_LIBRARY_DIRS "${Boost_LIBRARY_DIRS}/${CMAKE_ANDROID_ARCH_ABI}/")
  set(Boost_LIBRARIES "${Boost_LIBRARY_DIRS}libboost_log.a;${Boost_LIBRARY_DIRS}libboost_regex.a")
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
