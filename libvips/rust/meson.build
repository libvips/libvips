# Shared FFI/helper crate for in-tree Rust operations, linked into each
# operation crate as an rlib (meson passes --extern automatically).
#
# The GObject/libvips declarations are generated from the real headers with
# bindgen, so struct layout is derived by libclang exactly like the C
# compiler does; only the helper logic in vips_ffi.rs is hand-written.
rust_mod = import('rust')

vips_rust_bindings = rust_mod.bindgen(
    input: 'wrapper.h',
    output: 'bindings.rs',
    include_directories: libvips_includedir,
    # libvips_headers_dep also orders us after the generated
    # vips/version.h and vips/enumtypes.h
    dependencies: [libvips_headers_dep, glib_dep, gio_dep, gobject_dep],
    args: [
        '--allowlist-function',
        '(vips_error|vips_argument_get_id|vips_foreign_load_get_type' +
        '|vips_object_(set|get)_property|vips_object_class_install_argument' +
        '|vips_image_(init_fields|pipelinev|write_line)' +
        '|g_type_register_static|g_param_spec_string' +
        '|g_object_class_install_property)',
        '--allowlist-type', '(VipsForeignLoad|VipsForeignLoadClass|GTypeInfo)',
        '--default-enum-style', 'consts',
        '--no-doc-comments',
        '--no-layout-tests',
    ],
)

vips_ffi_lib = static_library('vips_ffi',
    structured_sources(['vips_ffi.rs', vips_rust_bindings]),
    rust_abi: 'rust',
    # LTO in the final static library needs rlib bitcode
    rust_args: ['--edition=2021', '-Cembed-bitcode=yes'],
)
