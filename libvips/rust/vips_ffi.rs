//! Helpers for implementing vips operations in Rust.
//!
//! Built as an rlib (see meson.build here) and shared by every in-tree Rust
//! operation, eg. foreign/bmpload.rs.
//!
//! All GObject/libvips declarations (structs, functions, enum constants)
//! live in the bindings module, generated from the real headers with
//! bindgen at build time — layout is derived by libclang exactly like the
//! C compiler derives it, so there is nothing to keep in sync by hand.
//! This file only adds the small amount of logic every operation needs:
//! type registration, argument installation and error reporting.

#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    dead_code,
    clippy::all
)]
mod bindings;

pub use bindings::*;

use std::ffi::{c_int, c_uint, c_void, CStr, CString};
use std::mem::size_of;
use std::ptr;

// Ergonomic aliases for the generated constants used by loaders.
pub const INTERPRETATION_SRGB: VipsInterpretation =
    VipsInterpretation_VIPS_INTERPRETATION_sRGB;
pub const INTERPRETATION_B_W: VipsInterpretation =
    VipsInterpretation_VIPS_INTERPRETATION_B_W;

// VIPS_ARGUMENT_REQUIRED_INPUT is an arithmetic macro in C, which bindgen
// cannot evaluate; compose it from the generated flag constants instead.
const ARGUMENT_REQUIRED_INPUT: VipsArgumentFlags = VipsArgumentFlags_VIPS_ARGUMENT_INPUT
    | VipsArgumentFlags_VIPS_ARGUMENT_REQUIRED
    | VipsArgumentFlags_VIPS_ARGUMENT_CONSTRUCT;

/// Set the vips error buffer and return -1, for use in vfuncs.
pub fn error(domain: &CStr, message: &str) -> c_int {
    let msg = CString::new(message).unwrap_or_default();
    unsafe { vips_error(domain.as_ptr(), c"%s".as_ptr(), msg.as_ptr()) };
    -1
}

/// Set the header fields for a simple 8-bit image and hint THINSTRIP demand.
pub unsafe fn image_init(image: *mut VipsImage, width: c_int, height: c_int,
    bands: c_int, interpretation: VipsInterpretation) -> c_int {
    vips_image_init_fields(image, width, height, bands,
        VipsBandFormat_VIPS_FORMAT_UCHAR, VipsCoding_VIPS_CODING_NONE,
        interpretation, 1.0, 1.0);
    vips_image_pipelinev(image, VipsDemandStyle_VIPS_DEMAND_STYLE_THINSTRIP,
        ptr::null_mut::<c_void>())
}

/// Write one scanline; line must be width * bands bytes.
pub unsafe fn write_line(image: *mut VipsImage, y: c_int, line: &[u8]) -> c_int {
    vips_image_write_line(image, y, line.as_ptr() as *mut VipsPel)
}

/// Install a required string argument (eg. "filename"), the equivalent of
/// VIPS_ARG_STRING(). offset is the field's byte offset in the instance
/// struct, from offset_of!().
pub unsafe fn install_string_argument(class: *mut VipsForeignLoadClass, name: &CStr,
    nick: &CStr, blurb: &CStr, offset: usize) {
    let pspec = g_param_spec_string(name.as_ptr(), nick.as_ptr(), blurb.as_ptr(),
        ptr::null(), GParamFlags_G_PARAM_READWRITE);
    g_object_class_install_property(class as *mut GObjectClass,
        vips_argument_get_id() as c_uint, pspec);
    vips_object_class_install_argument(class as *mut VipsObjectClass, pspec,
        ARGUMENT_REQUIRED_INPUT, 1, offset as c_uint);
}

pub type ClassInitFn = unsafe extern "C" fn(*mut VipsForeignLoadClass);

/// GLib does not inherit set/get_property into derived classes; re-set them
/// to the vips implementations before handing over to the subclass, so
/// install_string_argument() works. The subclass class_init fn travels in
/// via class_data.
unsafe extern "C" fn class_init_trampoline(class: gpointer, data: gpointer) {
    let gobject_class = class as *mut GObjectClass;
    (*gobject_class).set_property = Some(vips_object_set_property);
    (*gobject_class).get_property = Some(vips_object_get_property);
    let class_init: ClassInitFn = std::mem::transmute(data);
    class_init(class as *mut VipsForeignLoadClass);
}

/// Register a VipsForeignLoad subclass. instance_size is
/// size_of::<YourInstanceStruct>(); GObject zero-fills instances, so an
/// instance_init is rarely needed and not supported here.
pub unsafe fn register_load_class(type_name: &CStr, instance_size: usize,
    class_init: ClassInitFn) -> GType {
    assert!(instance_size >= size_of::<VipsForeignLoad>()
        && instance_size <= u16::MAX as usize);

    let info = GTypeInfo {
        class_size: size_of::<VipsForeignLoadClass>() as u16,
        base_init: None,
        base_finalize: None,
        class_init: Some(class_init_trampoline),
        class_finalize: None,
        class_data: class_init as *const c_void,
        instance_size: instance_size as u16,
        n_preallocs: 0,
        instance_init: None,
        value_table: ptr::null(),
    };
    g_type_register_static(vips_foreign_load_get_type(), type_name.as_ptr(), &info, 0)
}
