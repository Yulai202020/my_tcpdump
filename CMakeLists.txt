cmake_minimum_required(VERSION 3.30)

project(tcpdump)

find_library(JSONC_LIBRARY NAMES json-c)
find_library(PCAP_LIBRARY NAMES pcap)

add_executable(${PROJECT_NAME} main.c table.c)

target_link_libraries(${PROJECT_NAME} PUBLIC ${JSONC_LIBRARY} ${PCAP_LIBRARY})