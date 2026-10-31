# -----------------------------------------------------------------------------
# BPF kernel programs for the packet engine.
#
# Builds `bpf/af_xdp_kern.bpf.c` -> `<build>/bpf/af_xdp_kern.o` via clang with
# the BPF target.  The object is later loaded and pinned by the user-space loader
# (see Task 8) and attached to the NIC's XDP hook.
#
# Toolchain requirements (provided by the nix dev shell in `devenv.nix`):
#   - clang >= 14 with BPF target support (`-target bpf`)
#   - llvm-objdump for verification
#   - libxdp / libbpf headers (via pkg-config)
#
# Output is placed below the active build tree.  This keeps clean and parallel
# builds isolated while retaining the relative runtime path `bpf/af_xdp_kern.o`
# when the engine is launched from its build directory.
# -----------------------------------------------------------------------------

# Required only when actually building BPF objects; allow configure without it.
find_package(PkgConfig REQUIRED)

pkg_check_modules(LIBXDP REQUIRED libxdp)
pkg_check_modules(LIBBPF REQUIRED libbpf)

# Locate clang with BPF target support.  Honour the env override used by CI /
# nix shells, then fall back to the system clang.
if(NOT DEFINED ENV{CLANG})
  set(_clang_candidates clang clang-18 clang-17 clang-16 clang-15 clang-14)
else()
  set(_clang_candidates $ENV{CLANG})
endif()

find_program(CLANG_BPF_EXE
  NAMES ${_clang_candidates}
  DOC   "clang with BPF target support"
)

if(NOT CLANG_BPF_EXE)
  message(FATAL_ERROR
    "clang with BPF target support is required to build BPF objects. "
    "Install clang >= 14 or run inside `nix develop`."
  )
endif()

# Probe for BPF target support so we fail fast at configure time rather than
# at the first build.
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/_clang_bpf_probe.c"
  "int bpf_probe(void) { return 0; }\n"
)

execute_process(
  COMMAND ${CLANG_BPF_EXE} -target bpf
          -I${LIBBPF_INCLUDE_DIRS}
          -c "${CMAKE_CURRENT_BINARY_DIR}/_clang_bpf_probe.c"
          -o "${CMAKE_CURRENT_BINARY_DIR}/_clang_bpf_probe.o"
  RESULT_VARIABLE _clang_bpf_rc
  OUTPUT_VARIABLE _clang_bpf_out
  ERROR_VARIABLE  _clang_bpf_err
)
if(NOT _clang_bpf_rc EQUAL 0)
  message(FATAL_ERROR
    "clang (${CLANG_BPF_EXE}) does not support the BPF target.\n"
    "stderr:\n${_clang_bpf_err}"
  )
endif()

if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64|AMD64)$")
  set(BPF_TARGET_ARCH x86)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64)$")
  set(BPF_TARGET_ARCH arm64)
else()
  message(FATAL_ERROR
    "Unsupported BPF target architecture: ${CMAKE_SYSTEM_PROCESSOR}"
  )
endif()

set(BPF_CFLAGS
  -target            bpf
  -D__TARGET_ARCH_${BPF_TARGET_ARCH}
  -Wall
  -O2
  -g
  -Wno-pointer-sign
  -fno-stack-protector
)

# Debian and Ubuntu keep <asm/types.h> in the architecture-specific include
# directory, which clang does not add implicitly for a -target bpf compile.
find_path(ASM_TYPES_INCLUDE_DIR
  NAMES asm/types.h
  PATHS /usr/include/${CMAKE_LIBRARY_ARCHITECTURE}
  NO_DEFAULT_PATH
)
if(ASM_TYPES_INCLUDE_DIR)
  list(APPEND BPF_CFLAGS -I${ASM_TYPES_INCLUDE_DIR})
endif()

# -----------------------------------------------------------------------------
# af_xdp_kern.o  --  AF_XDP redirect XDP program
# -----------------------------------------------------------------------------
set(_bpf_src  ${CMAKE_CURRENT_SOURCE_DIR}/af_xdp_kern.bpf.c)
set(_bpf_out  ${CMAKE_CURRENT_BINARY_DIR}/af_xdp_kern.o)

add_custom_command(
  OUTPUT  ${_bpf_out}
  COMMAND ${CLANG_BPF_EXE} ${BPF_CFLAGS}
          -I${LIBXDP_INCLUDE_DIRS}
          -I${LIBBPF_INCLUDE_DIRS}
          -c ${_bpf_src}
          -o ${_bpf_out}
  DEPENDS ${_bpf_src}
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  COMMENT "clang [bpf] af_xdp_kern.bpf.c -> af_xdp_kern.o"
  VERBATIM
  COMMAND_EXPAND_LISTS
)

add_custom_target(af_xdp_kern ALL DEPENDS ${_bpf_out})

# Convenience target: dump the disassembly so a developer can quickly inspect
# the BPF bytecode after changes.
find_program(LLVM_OBJDUMP_EXE
  NAMES llvm-objdump objdump
  DOC   "llvm-objdump (preferred) for BPF disassembly"
)

if(LLVM_OBJDUMP_EXE)
  add_custom_target(af_xdp_kern_disasm
    COMMAND ${LLVM_OBJDUMP_EXE} -d ${_bpf_out}
    DEPENDS ${_bpf_out}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "llvm-objdump -d bpf/af_xdp_kern.o"
    VERBATIM
  )
endif()
