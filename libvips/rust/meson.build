# Shared FFI/helper crate for in-tree Rust operations, linked into each
# operation crate as an rlib (meson passes --extern automatically).
vips_ffi_lib = static_library('vips_ffi',
    'vips_ffi.rs',
    rust_abi: 'rust',
    rust_args: ['--edition=2021'],
)
