//! Minimal GObject/libvips FFI for implementing vips operations in Rust.
//!
//! Built as an rlib (see meson.build here) and shared by every in-tree Rust
//! operation, eg. foreign/bmpload.rs. This is the hand-written seed of what
//! should eventually be a bindgen-generated vips-sys plus a safe
//! vips-subclass layer.
//!
//! The structs below are the stable public ABI of gobject/gobject.h,
//! vips/object.h, vips/operation.h and vips/foreign.h, flattened to just the
//! fields subclasses touch; everything else is opaque padding.
//! register_load_class() cross-checks the sizes with g_type_query() at
//! runtime, so ABI drift fails loudly instead of corrupting memory.

use std::ffi::{c_char, c_double, c_int, c_uint, c_void, CStr, CString};
use std::mem::size_of;

pub type GType = usize;
pub type VipsImage = c_void; // opaque, only used via accessor functions

// --- flattened class / instance structs -------------------------------------

/// GObjectClass..VipsForeignLoadClass. Set the pub fields in your class_init.
#[repr(C)]
pub struct ForeignLoadClass {
    _gobject: [usize; 3],
    set_property: *mut c_void, // set by the class_init trampoline
    get_property: *mut c_void,
    _gobject_rest: [usize; 12],
    _vips_object_vfuncs: [usize; 14],
    pub nickname: *const c_char,
    pub description: *const c_char,
    _vips_object_rest: [usize; 8],
    _vips_operation: [usize; 4],
    _priority: usize,
    pub suffs: *const *const c_char,
    pub is_a: Option<unsafe extern "C" fn(*const c_char) -> c_int>,
    pub is_a_buffer: Option<unsafe extern "C" fn(*const c_void, usize) -> c_int>,
    pub is_a_source: Option<unsafe extern "C" fn(*mut c_void) -> c_int>,
    pub get_flags_filename: Option<unsafe extern "C" fn(*const c_char) -> c_int>,
    pub get_flags: Option<unsafe extern "C" fn(*mut ForeignLoad) -> c_int>,
    pub header: Option<unsafe extern "C" fn(*mut ForeignLoad) -> c_int>,
    pub load: Option<unsafe extern "C" fn(*mut ForeignLoad) -> c_int>,
}

/// GObject..VipsForeignLoad instance. Subclasses embed this as their first
/// field (#[repr(C)]) and add their own fields after it.
#[repr(C)]
pub struct ForeignLoad {
    _parent: [usize; 15],
    pub out: *mut VipsImage,
    pub real: *mut VipsImage,
    _rest: [usize; 2],
}

// --- constants ---------------------------------------------------------------

pub const FORMAT_UCHAR: c_int = 0;
pub const CODING_NONE: c_int = 0;
pub const INTERPRETATION_B_W: c_int = 1;
pub const INTERPRETATION_SRGB: c_int = 22;
pub const DEMAND_THINSTRIP: c_int = 2;

const G_PARAM_READWRITE: c_uint = 3;
const ARGUMENT_REQUIRED_INPUT: c_uint = 19; // INPUT | REQUIRED | CONSTRUCT

// --- libvips / GObject entry points we wrap ----------------------------------

#[repr(C)]
struct GTypeInfo {
    class_size: u16,
    _base: [usize; 2],
    class_init: unsafe extern "C" fn(*mut ForeignLoadClass, *mut c_void),
    _class_finalize: usize,
    class_data: *const c_void,
    instance_size: u16,
    n_preallocs: u16,
    instance_init: usize,
    value_table: usize,
}

#[repr(C)]
#[derive(Default)]
struct GTypeQuery {
    type_: GType,
    type_name: usize,
    class_size: c_uint,
    instance_size: c_uint,
}

extern "C" {
    fn g_type_register_static(p: GType, n: *const c_char, i: *const GTypeInfo, f: c_uint) -> GType;
    fn g_type_query(t: GType, q: *mut GTypeQuery);
    fn g_param_spec_string(n: *const c_char, nick: *const c_char, blurb: *const c_char,
        def: *const c_char, flags: c_uint) -> *mut c_void;
    fn g_object_class_install_property(c: *mut ForeignLoadClass, id: c_uint, pspec: *mut c_void);
    fn vips_foreign_load_get_type() -> GType;
    fn vips_argument_get_id() -> c_uint;
    fn vips_object_class_install_argument(c: *mut ForeignLoadClass, pspec: *mut c_void,
        flags: c_uint, priority: c_int, offset: c_uint);
    fn vips_object_set_property(o: *mut c_void, id: c_uint, v: *const c_void, p: *mut c_void);
    fn vips_object_get_property(o: *mut c_void, id: c_uint, v: *mut c_void, p: *mut c_void);
    fn vips_error(domain: *const c_char, fmt: *const c_char, ...);
    fn vips_image_init_fields(im: *mut VipsImage, w: c_int, h: c_int, bands: c_int, format: c_int,
        coding: c_int, interpretation: c_int, xres: c_double, yres: c_double);
    fn vips_image_pipelinev(im: *mut VipsImage, hint: c_int, ...) -> c_int;
    fn vips_image_write_line(im: *mut VipsImage, y: c_int, line: *const u8) -> c_int;
}

// --- helpers ------------------------------------------------------------------

/// Set the vips error buffer and return -1, for use in vfuncs.
pub fn error(domain: &CStr, message: &str) -> c_int {
    let msg = CString::new(message).unwrap_or_default();
    unsafe { vips_error(domain.as_ptr(), c"%s".as_ptr(), msg.as_ptr()) };
    -1
}

/// Set the header fields for a simple 8-bit image and hint THINSTRIP demand.
pub unsafe fn image_init(image: *mut VipsImage, width: c_int, height: c_int,
    bands: c_int, interpretation: c_int) -> c_int {
    vips_image_init_fields(image, width, height, bands,
        FORMAT_UCHAR, CODING_NONE, interpretation, 1.0, 1.0);
    vips_image_pipelinev(image, DEMAND_THINSTRIP, std::ptr::null_mut::<c_void>())
}

/// Write one scanline; line must be width * bands bytes.
pub unsafe fn write_line(image: *mut VipsImage, y: c_int, line: &[u8]) -> c_int {
    vips_image_write_line(image, y, line.as_ptr())
}

/// Install a required string argument (eg. "filename"), the equivalent of
/// VIPS_ARG_STRING(). offset is the field's byte offset in the instance
/// struct, from offset_of!().
pub unsafe fn install_string_argument(class: *mut ForeignLoadClass, name: &CStr,
    nick: &CStr, blurb: &CStr, offset: usize) {
    let pspec = g_param_spec_string(name.as_ptr(), nick.as_ptr(), blurb.as_ptr(),
        std::ptr::null(), G_PARAM_READWRITE);
    g_object_class_install_property(class, vips_argument_get_id(), pspec);
    vips_object_class_install_argument(class, pspec,
        ARGUMENT_REQUIRED_INPUT, 1, offset as c_uint);
}

pub type ClassInitFn = unsafe extern "C" fn(*mut ForeignLoadClass);

/// GLib does not inherit set/get_property into derived classes; re-set them
/// to the vips implementations before handing over to the subclass, so
/// install_string_argument() works. The subclass class_init fn travels in
/// via class_data.
unsafe extern "C" fn class_init_trampoline(class: *mut ForeignLoadClass, data: *mut c_void) {
    (*class).set_property = vips_object_set_property as *mut c_void;
    (*class).get_property = vips_object_get_property as *mut c_void;
    let class_init: ClassInitFn = std::mem::transmute(data);
    class_init(class);
}

/// Register a VipsForeignLoad subclass. instance_size is
/// size_of::<YourInstanceStruct>(); GObject zero-fills instances, so an
/// instance_init is rarely needed and not supported here.
pub unsafe fn register_load_class(type_name: &CStr, instance_size: usize,
    class_init: ClassInitFn) -> GType {
    let parent = vips_foreign_load_get_type();

    // guard against ABI drift in our flattened structs
    let mut q = GTypeQuery::default();
    g_type_query(parent, &mut q);
    assert_eq!(q.class_size as usize, size_of::<ForeignLoadClass>(),
        "vips_ffi: class ABI mismatch");
    assert_eq!(q.instance_size as usize, size_of::<ForeignLoad>(),
        "vips_ffi: instance ABI mismatch");
    assert!(instance_size >= size_of::<ForeignLoad>() && instance_size <= u16::MAX as usize);

    let info = GTypeInfo {
        class_size: size_of::<ForeignLoadClass>() as u16,
        _base: [0; 2],
        class_init: class_init_trampoline,
        _class_finalize: 0,
        class_data: class_init as *const c_void,
        instance_size: instance_size as u16,
        n_preallocs: 0,
        instance_init: 0,
        value_table: 0,
    };
    g_type_register_static(parent, type_name.as_ptr(), &info, 0)
}
