cmake_minimum_required (VERSION 3.8)

project("tor-connect")

#set(BOOST_ROOT "D:\\boost_1_72_0") # either set it here or from the command line  
SET(Boost_USE_STATIC_LIBS ON)           # link statically

add_library(tor-connect "tor-connect.cpp" "tor-connect.h" "torlib/torlib.cpp" "torlib/torlib.h" "torlib/Cell.cpp" "torlib/Cell.h" "torlib/Curve25519.cpp" "torlib/Curve25519.h" 
"torlib/NetConnect.cpp" "torlib/NetConnect.h" "torlib/OnionRouter.cpp" "torlib/OnionRouter.h" "torlib/Parser.cpp" "torlib/Parser.h" "torlib/RelayCell.cpp" "torlib/RelayCell.h" 
"torlib/Util.cpp" "torlib/Util.h")

target_compile_features(${PROJECT_NAME} PRIVATE cxx_std_17)

find_package(Boost 1.69.0 COMPONENTS log REQUIRED)
target_include_directories(${PROJECT_NAME} PUBLIC ${Boost_INCLUDE_DIRS}) 
target_link_libraries(${PROJECT_NAME} ${Boost_LIBRARIES})

find_package(OpenSSL REQUIRED)
target_include_directories(${PROJECT_NAME} PUBLIC ${OPENSSL_INCLUDE_DIR})
target_link_libraries(${PROJECT_NAME} OpenSSL::SSL OpenSSL::Crypto)
