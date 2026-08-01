//! load bmp from a file — a minimal Rust prototype
//!
//! Registers "bmpload", a VipsForeignLoad subclass. Deliberately tiny: it
//! only accepts the most common BMP variant (BITMAPINFOHEADER, 24-bit,
//! uncompressed, bottom-up) and rejects everything else with a clear error.
//!
//! Built by meson as a C-ABI static library (see -Drust) and registered from
//! vips_foreign_operation_init() like any other loader. The GObject/vips
//! plumbing lives in the shared vips_ffi crate, see libvips/rust/vips_ffi.rs.

use std::ffi::{c_char, c_int, CStr};
use std::mem::{offset_of, size_of};
use std::ptr;
use std::sync::OnceLock;

use vips_ffi as vips;
use vips_ffi::{ForeignLoad, ForeignLoadClass, GType, INTERPRETATION_SRGB};

const DOMAIN: &CStr = c"bmpload";

/// Parent instance plus storage for our "filename" argument, which
/// VipsObject manages through the offset we pass in class_init().
#[repr(C)]
struct Load {
    parent: ForeignLoad,
    filename: *mut c_char,
}

// --- the BMP subset we support ---------------------------------------------

struct Bmp {
    width: usize,
    height: usize,
    data_offset: usize,
    stride: usize,
}

/// Accept only: BITMAPINFOHEADER, 24-bit, uncompressed, bottom-up.
fn parse(b: &[u8]) -> Result<Bmp, &'static str> {
    if b.len() < 54 || &b[..2] != b"BM" {
        return Err("not a bmp file");
    }
    let le32 = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap()) as usize;

    let (width, height) = (le32(18), le32(22)); // negative values fail the range check
    let bpp = le32(26) >> 16;
    if le32(14) != 40 || bpp != 24 || le32(30) != 0 {
        return Err("unsupported bmp variant (prototype reads 24-bit uncompressed only)");
    }
    if !(1..=65535).contains(&width) || !(1..=65535).contains(&height) {
        return Err("bad image dimensions");
    }

    let stride = (3 * width + 3) & !3; // rows padded to 4 bytes
    let data_offset = le32(10);
    if data_offset < 54 || data_offset + stride * height > b.len() {
        return Err("truncated pixel data");
    }

    Ok(Bmp { width, height, data_offset, stride })
}

fn read_file(load: *mut ForeignLoad) -> Result<Vec<u8>, String> {
    let filename = unsafe { (*(load as *mut Load)).filename };
    if filename.is_null() {
        return Err("no filename set".into());
    }
    let filename = unsafe { CStr::from_ptr(filename) }.to_string_lossy();
    std::fs::read(&*filename).map_err(|e| format!("unable to read \"{filename}\": {e}"))
}

// --- vfuncs -----------------------------------------------------------------

unsafe extern "C" fn bmp_is_a(filename: *const c_char) -> c_int {
    use std::io::Read;
    let mut head = [0u8; 54];
    std::fs::File::open(&*CStr::from_ptr(filename).to_string_lossy())
        .and_then(|mut f| f.read_exact(&mut head))
        .is_ok_and(|()| &head[..2] == b"BM") as c_int
}

unsafe extern "C" fn bmp_header(load: *mut ForeignLoad) -> c_int {
    match read_file(load).and_then(|b| parse(&b).map_err(String::from)) {
        Ok(bmp) => vips::image_init((*load).out,
            bmp.width as c_int, bmp.height as c_int, 3, INTERPRETATION_SRGB),
        Err(e) => vips::error(DOMAIN, &e),
    }
}

unsafe extern "C" fn bmp_load(load: *mut ForeignLoad) -> c_int {
    let bytes = match read_file(load) {
        Ok(b) => b,
        Err(e) => return vips::error(DOMAIN, &e),
    };
    let Ok(bmp) = parse(&bytes) else {
        return vips::error(DOMAIN, "bad bmp"); // validated in header(), can't happen
    };
    if vips::image_init((*load).real,
        bmp.width as c_int, bmp.height as c_int, 3, INTERPRETATION_SRGB) != 0 {
        return -1;
    }

    let mut line = vec![0u8; 3 * bmp.width];
    for y in 0..bmp.height {
        // rows are stored bottom-up, pixels as BGR
        let row = &bytes[bmp.data_offset + (bmp.height - 1 - y) * bmp.stride..];
        for x in 0..bmp.width {
            line[3 * x] = row[3 * x + 2];
            line[3 * x + 1] = row[3 * x + 1];
            line[3 * x + 2] = row[3 * x];
        }
        if vips::write_line((*load).real, y as c_int, &line) != 0 {
            return -1;
        }
    }

    0
}

// --- type registration --------------------------------------------------------

unsafe extern "C" fn class_init(class: *mut ForeignLoadClass) {
    struct Suffs([*const c_char; 3]);
    unsafe impl Sync for Suffs {}
    static SUFFS: Suffs = Suffs([c".bmp".as_ptr(), c".dib".as_ptr(), ptr::null()]);

    (*class).nickname = c"bmpload".as_ptr();
    (*class).description = c"load bmp from file".as_ptr();
    (*class).suffs = SUFFS.0.as_ptr();
    (*class).is_a = Some(bmp_is_a);
    (*class).header = Some(bmp_header);
    (*class).load = Some(bmp_load);

    vips::install_string_argument(class, c"filename", c"Filename",
        c"Filename to load from", offset_of!(Load, filename));
}

/// Called from vips_foreign_operation_init() in foreign.c.
#[no_mangle]
pub extern "C" fn vips_foreign_load_bmp_file_get_type() -> GType {
    static TYPE: OnceLock<GType> = OnceLock::new();

    *TYPE.get_or_init(|| unsafe {
        vips::register_load_class(c"VipsForeignLoadBmpFile", size_of::<Load>(), class_init)
    })
}
