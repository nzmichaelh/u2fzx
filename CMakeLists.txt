include($ENV{ZEPHYR_BASE}/cmake/app/boilerplate.cmake NO_POLICY_SCOPE)
project(NONE)

add_definitions(-D_GLIBCXX_STDEXCEPT)

zephyr_include_directories(
  src
)

FILE(GLOB app_sources src/*.c src/*.cpp)
target_sources(app PRIVATE ${app_sources})
