# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.22

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/lucifer/KeyManageServer

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/lucifer/KeyManageServer/build

# Utility rule file for upload-tars.

# Include any custom commands dependencies for this target.
include CMakeFiles/upload-tars.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/upload-tars.dir/progress.make

CMakeFiles/upload-tars:
	/usr/bin/cmake -P /home/lucifer/KeyManageServer/build/run-upload-tars.cmake

upload-tars: CMakeFiles/upload-tars
upload-tars: CMakeFiles/upload-tars.dir/build.make
.PHONY : upload-tars

# Rule to build all files generated by this target.
CMakeFiles/upload-tars.dir/build: upload-tars
.PHONY : CMakeFiles/upload-tars.dir/build

CMakeFiles/upload-tars.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/upload-tars.dir/cmake_clean.cmake
.PHONY : CMakeFiles/upload-tars.dir/clean

CMakeFiles/upload-tars.dir/depend:
	cd /home/lucifer/KeyManageServer/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/lucifer/KeyManageServer /home/lucifer/KeyManageServer /home/lucifer/KeyManageServer/build /home/lucifer/KeyManageServer/build /home/lucifer/KeyManageServer/build/CMakeFiles/upload-tars.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/upload-tars.dir/depend

