add_library(nr_phy_common src/nr_phy_common.c)
target_link_libraries(nr_phy_common PRIVATE UTIL)
target_include_directories(nr_phy_common PUBLIC inc/)
