cmake_minimum_required(VERSION 3.23)
project(min_back C)

add_executable(min_back min_back.c)
target_compile_features(min_back PRIVATE c_std_11)
