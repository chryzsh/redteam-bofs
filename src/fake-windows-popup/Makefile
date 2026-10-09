BUILD_DIR := build-mingw
TEST_BUILD_DIR := build-tests
TOOLCHAIN := cmake/toolchains/mingw-x64.cmake
PE := $(BUILD_DIR)/fake-windows-popup.exe

.PHONY: all test inspect clean

all: $(BUILD_DIR)/CMakeCache.txt
	cmake --build $(BUILD_DIR) --target fake-windows-popup -j2

$(BUILD_DIR)/CMakeCache.txt: CMakeLists.txt $(TOOLCHAIN)
	cmake -S . -B $(BUILD_DIR) \
		-DCMAKE_TOOLCHAIN_FILE=$(TOOLCHAIN) \
		-DCMAKE_BUILD_TYPE=Release

test: $(TEST_BUILD_DIR)/CMakeCache.txt
	cmake --build $(TEST_BUILD_DIR) -j2
	ctest --test-dir $(TEST_BUILD_DIR) --output-on-failure

$(TEST_BUILD_DIR)/CMakeCache.txt: tests/CMakeLists.txt
	cmake -S tests -B $(TEST_BUILD_DIR) -DCMAKE_BUILD_TYPE=Debug

inspect: all
	x86_64-w64-mingw32-objdump -p $(PE)

clean:
	cmake -E remove_directory $(BUILD_DIR)
	cmake -E remove_directory $(TEST_BUILD_DIR)
