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

# Utility rule file for KeyManageServer-k8s-upload.

# Include any custom commands dependencies for this target.
include src/CMakeFiles/KeyManageServer-k8s-upload.dir/compiler_depend.make

# Include the progress variables for this target.
include src/CMakeFiles/KeyManageServer-k8s-upload.dir/progress.make

src/CMakeFiles/KeyManageServer-k8s-upload:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/lucifer/KeyManageServer/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "call /home/lucifer/KeyManageServer/build/run-k8s-upload-KeyManageServer.cmake"
	cmake -P /home/lucifer/KeyManageServer/build/run-k8s-upload-KeyManageServer.cmake

KeyManageServer-k8s-upload: src/CMakeFiles/KeyManageServer-k8s-upload
KeyManageServer-k8s-upload: src/CMakeFiles/KeyManageServer-k8s-upload.dir/build.make
.PHONY : KeyManageServer-k8s-upload

# Rule to build all files generated by this target.
src/CMakeFiles/KeyManageServer-k8s-upload.dir/build: KeyManageServer-k8s-upload
.PHONY : src/CMakeFiles/KeyManageServer-k8s-upload.dir/build

src/CMakeFiles/KeyManageServer-k8s-upload.dir/clean:
	cd /home/lucifer/KeyManageServer/build/src && $(CMAKE_COMMAND) -P CMakeFiles/KeyManageServer-k8s-upload.dir/cmake_clean.cmake
.PHONY : src/CMakeFiles/KeyManageServer-k8s-upload.dir/clean

src/CMakeFiles/KeyManageServer-k8s-upload.dir/depend:
	cd /home/lucifer/KeyManageServer/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/lucifer/KeyManageServer /home/lucifer/KeyManageServer/src /home/lucifer/KeyManageServer/build /home/lucifer/KeyManageServer/build/src /home/lucifer/KeyManageServer/build/src/CMakeFiles/KeyManageServer-k8s-upload.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : src/CMakeFiles/KeyManageServer-k8s-upload.dir/depend

