cmake_minimum_required(VERSION 3.20)
project(CS2_Injector VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Enforce Windows platform
if(NOT WIN32)
    message(FATAL_ERROR "This injector is strictly Windows-only.")
endif()

# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------
set(SOURCES
    src/main.cpp
)

# ---------------------------------------------------------------------------
# Executable Target
# ---------------------------------------------------------------------------
add_executable(${PROJECT_NAME} ${SOURCES})

# Compiler Definitions
target_compile_definitions(${PROJECT_NAME} PRIVATE
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    STRICT
)

# Link Libraries (ntdll for NtSuspend/Resume)
target_link_libraries(${PROJECT_NAME} PRIVATE
    ntdll
)

# ---------------------------------------------------------------------------
# UAC Admin Privileges Handling
# ---------------------------------------------------------------------------
set(MANIFEST_PATH "${CMAKE_CURRENT_SOURCE_DIR}/resources/app.manifest")

if(MSVC)
    # MSVC: Direct linker flag embedding
    target_link_options(${PROJECT_NAME} PRIVATE
        "/MANIFESTUAC:level='requireAdministrator' uiAccess='false'"
    )
elseif(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    # MinGW/Clang: Fallback to Windows SDK mt.exe post-build
    find_program(MT_EXE mt.exe HINTS "$ENV{WindowsSdkDir}bin/$ENV{VSCMD_ARG_TGT_ARCH}")
    if(MT_EXE)
        add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
            COMMAND "${MT_EXE}" -manifest "${MANIFEST_PATH}" 
                    -outputresource:"$<TARGET_FILE:${PROJECT_NAME}>";#1
            COMMENT "Embedding UAC manifest via mt.exe..."
        )
    else()
        message(WARNING "mt.exe not found. UAC manifest will not be embedded. "
                        "Run the compiled binary as Administrator manually, or install Windows SDK.")
    endif()
endif()

# ---------------------------------------------------------------------------
# Output Configuration
# ---------------------------------------------------------------------------
set_target_properties(${PROJECT_NAME} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/bin"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/bin"
    OUTPUT_NAME "CS2_Injector"
    VS_DEBUGGER_COMMAND "$<TARGET_FILE:${PROJECT_NAME}>"
)

# Optional: Enable Multi-Processor Compilation for MSVC
if(MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE /MP)
endif()
