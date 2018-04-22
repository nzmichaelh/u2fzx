include($ENV{ZEPHYR_BASE}/cmake/app/boilerplate.cmake NO_POLICY_SCOPE)
project(NONE)

add_definitions(-D_GLIBCXX_STDEXCEPT)

zephyr_include_directories(
  src
)

target_sources(app PRIVATE
  src/buf.c
  src/crypto.cpp
  src/hid.cpp
  src/main.cpp
  src/sfs.c
  src/u2f.cpp
  src/ui.cpp
  src/util.cpp
  src/crypto_sam0.cpp
)
