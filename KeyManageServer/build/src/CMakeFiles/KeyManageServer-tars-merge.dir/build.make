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

# Utility rule file for KeyManageServer-tars-merge.

# Include any custom commands dependencies for this target.
include src/CMakeFiles/KeyManageServer-tars-merge.dir/compiler_depend.make

# Include the progress variables for this target.
include src/CMakeFiles/KeyManageServer-tars-merge.dir/progress.make

src/CMakeFiles/KeyManageServer-tars-merge:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/lucifer/KeyManageServer/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "merge tars"
	cd /home/lucifer/KeyManageServer/src && /usr/local/tars/cpp/tools/tarsmerge /home/lucifer/KeyManageServer/src/KeyManage.tars --out=/home/lucifer/KeyManageServer/build/KeyManageServer-merge.tars

KeyManageServer-tars-merge: src/CMakeFiles/KeyManageServer-tars-merge
KeyManageServer-tars-merge: src/CMakeFiles/KeyManageServer-tars-merge.dir/build.make
.PHONY : KeyManageServer-tars-merge

# Rule to build all files generated by this target.
src/CMakeFiles/KeyManageServer-tars-merge.dir/build: KeyManageServer-tars-merge
.PHONY : src/CMakeFiles/KeyManageServer-tars-merge.dir/build

src/CMakeFiles/KeyManageServer-tars-merge.dir/clean:
	cd /home/lucifer/KeyManageServer/build/src && $(CMAKE_COMMAND) -P CMakeFiles/KeyManageServer-tars-merge.dir/cmake_clean.cmake
.PHONY : src/CMakeFiles/KeyManageServer-tars-merge.dir/clean

src/CMakeFiles/KeyManageServer-tars-merge.dir/depend:
	cd /home/lucifer/KeyManageServer/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/lucifer/KeyManageServer /home/lucifer/KeyManageServer/src /home/lucifer/KeyManageServer/build /home/lucifer/KeyManageServer/build/src /home/lucifer/KeyManageServer/build/src/CMakeFiles/KeyManageServer-tars-merge.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : src/CMakeFiles/KeyManageServer-tars-merge.dir/depend

