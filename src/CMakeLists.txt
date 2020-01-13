project(Mm0205_Native_Mac_Keychain C)

set(MY_INCLUDE_DIRS ../include)

add_library(
        Mm0205_Native_Mac_Keychain SHARED
        mm0205_native_mac_keychain.c
)

target_include_directories(
        ${PROJECT_NAME}
        PUBLIC
        ${MY_INCLUDE_DIRS}
)

target_link_libraries(${PROJECT_NAME} "-framework CoreFoundation" "-framework Security")
