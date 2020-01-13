project(Mm0205_Native_Mac_Keychain_console_test)

set(
        MY_SOURCES
        main.c
)

add_executable(
        ${PROJECT_NAME}
        ${MY_SOURCES}
)

target_include_directories(${PROJECT_NAME} PUBLIC "../include")
target_link_libraries(${PROJECT_NAME} "Mm0205_Native_Mac_Keychain")
