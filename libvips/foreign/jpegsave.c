/* save to jpeg
 *
 * 24/11/11
 * 	- wrap a class around the jpeg writer
 */

/*

    This file is part of VIPS.
    
    VIPS is free software; you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
    02110-1301  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

/*
#define DEBUG_VERBOSE
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>

#include <vips/vips.h>
#include <vips/buf.h>
#include <vips/internal.h>

#ifdef HAVE_JPEG

#ifdef HAVE_EXIF
#ifdef UNTAGGED_EXIF
#include <exif-data.h>
#include <exif-loader.h>
#include <exif-ifd.h>
#include <exif-utils.h>
#else /*!UNTAGGED_EXIF*/
#include <libexif/exif-data.h>
#include <libexif/exif-loader.h>
#include <libexif/exif-ifd.h>
#include <libexif/exif-utils.h>
#endif /*UNTAGGED_EXIF*/
#endif /*HAVE_EXIF*/

#include "vipsjpeg.h"

typedef struct _VipsForeignSaveJpeg {
	VipsForeignSave parent_object;

	/* Quality factor.
	 */
	int Q;

	/* Profile to embed .. "none" means don't attach a profile.
	 */
	char *profile;

	/* Compute optimal Huffman coding tables.
	 */
	gboolean optimize_coding;

	/* Generate an interlaced (progressive, in jpg terminology) file.
	 */
	gboolean interlace;

	/* Disable chroma subsampling. 
	 */
	gboolean no_subsample;

	/* Apply trellis quantisation to each 8x8 block.
	 */
	gboolean trellis_quant;

	/* Apply overshooting to samples with extreme values e.g. 0 & 255 for 8-bit.
	 */
	gboolean overshoot_deringing;

	/* Split the spectrum of DCT coefficients into separate scans.
	 */
	gboolean optimize_scans;

	/* Use predefined quantization table with given index.
	 */
	int quant_table;

} VipsForeignSaveJpeg;

typedef VipsForeignSaveClass VipsForeignSaveJpegClass;

G_DEFINE_ABSTRACT_TYPE( VipsForeignSaveJpeg, vips_foreign_save_jpeg, 
	VIPS_TYPE_FOREIGN_SAVE );

#define UC VIPS_FORMAT_UCHAR

/* Type promotion for save ... just always go to uchar.
 */
static int bandfmt_jpeg[10] = {
/* UC  C   US  S   UI  I   F   X   D   DX */
   UC, UC, UC, UC, UC, UC, UC, UC, UC, UC
};

static void
vips_foreign_save_jpeg_class_init( VipsForeignSaveJpegClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignSaveClass *save_class = (VipsForeignSaveClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "jpegsave_base";
	object_class->description = _( "save jpeg" );

	foreign_class->suffs = vips__jpeg_suffs;

	save_class->saveable = VIPS_SAVEABLE_RGB_CMYK;
	save_class->format_table = bandfmt_jpeg;

	VIPS_ARG_INT( class, "Q", 10, 
		_( "Q" ), 
		_( "Q factor" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveJpeg, Q ),
		1, 100, 75 );

	VIPS_ARG_STRING( class, "profile", 11, 
		_( "Profile" ), 
		_( "ICC profile to embed" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveJpeg, profile ),
		NULL );

	VIPS_ARG_BOOL( class, "optimize_coding", 12,
		_( "Optimize_coding" ),
		_( "Compute optimal Huffman coding tables" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveJpeg, optimize_coding ),
		FALSE );

	VIPS_ARG_BOOL( class, "interlace", 13,
		_( "Interlace" ),
		_( "Generate an interlaced (progressive) jpeg" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveJpeg, interlace ),
		FALSE );

	VIPS_ARG_BOOL( class, "no_subsample", 14,
		_( "No subsample" ),
		_( "Disable chroma subsample" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveJpeg, no_subsample ),
		FALSE );

	VIPS_ARG_BOOL( class, "trellis_quant", 15,
		_( "Trellis quantisation" ),
		_( "Apply trellis quantisation to each 8x8 block" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveJpeg, trellis_quant ),
		FALSE );

	VIPS_ARG_BOOL( class, "overshoot_deringing", 16,
		_( "Overshoot de-ringing" ),
		_( "Apply overshooting to samples with extreme values" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveJpeg, overshoot_deringing ),
		FALSE );

	VIPS_ARG_BOOL( class, "optimize_scans", 17,
		_( "Optimize scans" ),
		_( "Split the spectrum of DCT coefficients into separate scans" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveJpeg, optimize_scans ),
		FALSE );

	VIPS_ARG_INT( class, "quant_table", 18,
		_( "Quantization table" ),
		_( "Use predefined quantization table with given index" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveJpeg, quant_table ),
		0, 8, 0 );

}

static void
vips_foreign_save_jpeg_init( VipsForeignSaveJpeg *jpeg )
{
	jpeg->Q = 75;
}

typedef struct _VipsForeignSaveJpegFile {
	VipsForeignSaveJpeg parent_object;

	/* Filename for save.
	 */
	char *filename; 

} VipsForeignSaveJpegFile;

typedef VipsForeignSaveJpegClass VipsForeignSaveJpegFileClass;

G_DEFINE_TYPE( VipsForeignSaveJpegFile, vips_foreign_save_jpeg_file, 
	vips_foreign_save_jpeg_get_type() );

static int
vips_foreign_save_jpeg_file_build( VipsObject *object )
{
	VipsForeignSave *save = (VipsForeignSave *) object;
	VipsForeignSaveJpeg *jpeg = (VipsForeignSaveJpeg *) object;
	VipsForeignSaveJpegFile *file = (VipsForeignSaveJpegFile *) object;

	if( VIPS_OBJECT_CLASS( vips_foreign_save_jpeg_file_parent_class )->
		build( object ) )
		return( -1 );

	if( vips__jpeg_write_file( save->ready, file->filename,
		jpeg->Q, jpeg->profile, jpeg->optimize_coding, 
		jpeg->interlace, save->strip, jpeg->no_subsample,
		jpeg->trellis_quant, jpeg->overshoot_deringing,
		jpeg->optimize_scans, jpeg->quant_table ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_save_jpeg_file_class_init( VipsForeignSaveJpegFileClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "jpegsave";
	object_class->description = _( "save image to jpeg file" );
	object_class->build = vips_foreign_save_jpeg_file_build;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to save to" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignSaveJpegFile, filename ),
		NULL );
}

static void
vips_foreign_save_jpeg_file_init( VipsForeignSaveJpegFile *file )
{
}

typedef struct _VipsForeignSaveJpegBuffer {
	VipsForeignSaveJpeg parent_object;

	/* Save to a buffer.
	 */
	VipsArea *buf;

} VipsForeignSaveJpegBuffer;

typedef VipsForeignSaveJpegClass VipsForeignSaveJpegBufferClass;

G_DEFINE_TYPE( VipsForeignSaveJpegBuffer, vips_foreign_save_jpeg_buffer, 
	vips_foreign_save_jpeg_get_type() );

static int
vips_foreign_save_jpeg_buffer_build( VipsObject *object )
{
	VipsForeignSave *save = (VipsForeignSave *) object;
	VipsForeignSaveJpeg *jpeg = (VipsForeignSaveJpeg *) object;
	VipsForeignSaveJpegBuffer *file = (VipsForeignSaveJpegBuffer *) object;

	void *obuf;
	size_t olen;
	VipsBlob *blob;

	if( VIPS_OBJECT_CLASS( vips_foreign_save_jpeg_buffer_parent_class )->
		build( object ) )
		return( -1 );

	if( vips__jpeg_write_buffer( save->ready, 
		&obuf, &olen, jpeg->Q, jpeg->profile, jpeg->optimize_coding, 
		jpeg->interlace, save->strip, jpeg->no_subsample,
		jpeg->trellis_quant, jpeg->overshoot_deringing,
		jpeg->optimize_scans, jpeg->quant_table ) )
		return( -1 );

	/* obuf is a g_free() buffer, not vips_free().
	 */
	blob = vips_blob_new( (VipsCallbackFn) g_free, obuf, olen );
	g_object_set( file, "buffer", blob, NULL );
	vips_area_unref( VIPS_AREA( blob ) );

	return( 0 );
}

static void
vips_foreign_save_jpeg_buffer_class_init( 
	VipsForeignSaveJpegBufferClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "jpegsave_buffer";
	object_class->description = _( "save image to jpeg buffer" );
	object_class->build = vips_foreign_save_jpeg_buffer_build;

	VIPS_ARG_BOXED( class, "buffer", 1, 
		_( "Buffer" ),
		_( "Buffer to save to" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsForeignSaveJpegBuffer, buf ),
		VIPS_TYPE_BLOB );
}

static void
vips_foreign_save_jpeg_buffer_init( VipsForeignSaveJpegBuffer *file )
{
}

typedef struct _VipsForeignSaveJpegMime {
	VipsForeignSaveJpeg parent_object;

} VipsForeignSaveJpegMime;

typedef VipsForeignSaveJpegClass VipsForeignSaveJpegMimeClass;

G_DEFINE_TYPE( VipsForeignSaveJpegMime, vips_foreign_save_jpeg_mime, 
	vips_foreign_save_jpeg_get_type() );

static int
vips_foreign_save_jpeg_mime_build( VipsObject *object )
{
	VipsForeignSave *save = (VipsForeignSave *) object;
	VipsForeignSaveJpeg *jpeg = (VipsForeignSaveJpeg *) object;

	void *obuf;
	size_t olen;

	if( VIPS_OBJECT_CLASS( vips_foreign_save_jpeg_mime_parent_class )->
		build( object ) )
		return( -1 );

	if( vips__jpeg_write_buffer( save->ready, 
		&obuf, &olen, jpeg->Q, jpeg->profile, jpeg->optimize_coding, 
		jpeg->interlace, save->strip, jpeg->no_subsample,
		jpeg->trellis_quant, jpeg->overshoot_deringing,
		jpeg->optimize_scans, jpeg->quant_table ) )
		return( -1 );

	printf( "Content-length: %zu\r\n", olen );
	printf( "Content-type: image/jpeg\r\n" );
	printf( "\r\n" );
	if( fwrite( obuf, sizeof( char ), olen, stdout ) != olen ) {
		vips_error( "VipsJpeg", "%s", _( "error writing output" ) );
		return( -1 );
	}
	fflush( stdout );

	g_free( obuf );

	return( 0 );
}

static void
vips_foreign_save_jpeg_mime_class_init( VipsForeignSaveJpegMimeClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	object_class->nickname = "jpegsave_mime";
	object_class->description = _( "save image to jpeg mime" );
	object_class->build = vips_foreign_save_jpeg_mime_build;

}

static void
vips_foreign_save_jpeg_mime_init( VipsForeignSaveJpegMime *mime )
{
}

#endif /*HAVE_JPEG*/

/**
 * vips_jpegsave:
 * @in: image to save 
 * @filename: file to write to 
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @Q: %gint, quality factor
 * * @profile: filename of ICC profile to attach
 * * @optimize_coding: %gboolean, compute optimal Huffman coding tables
 * * @interlace: %gboolean, write an interlaced (progressive) jpeg
 * * @strip: %gboolean, remove all metadata from image
 * * @no-subsample: %gboolean, disable chroma subsampling
 * * @trellis_quant: %gboolean, apply trellis quantisation to each 8x8 block
 * * @overshoot_deringing: %gboolean, overshoot samples with extreme values
 * * @optimize_scans: %gboolean, split DCT coefficients into separate scans
 * * @quant_table: %gint, quantization table index
 *
 * Write a VIPS image to a file as JPEG.
 *
 * Use @Q to set the JPEG compression factor. Default 75.
 *
 * Use @profile to give the filename of a profile to be embedded in the JPEG.
 * This does not affect the pixels which are written, just the way 
 * they are tagged. You can use the special string "none" to mean 
 * "don't attach a profile".
 *
 * If no profile is specified and the VIPS header 
 * contains an ICC profile named #VIPS_META_ICC_NAME, the
 * profile from the VIPS header will be attached.
 *
 * If @optimize_coding is set, the Huffman tables are optimised. This is
 * sllightly slower and produces slightly smaller files. 
 *
 * If @interlace is set, the jpeg files will be interlaced (progressive jpeg,
 * in jpg parlance). These files may be better for display over a slow network
 * conection, but need much more memory to encode and decode. 
 *
 * If @strip is set, no EXIF data, IPCT data, ICC profile or XMP metadata is 
 * written into the output file. 
 *
 * If @no-subsample is set, chrominance subsampling is disabled. This will 
 * improve quality at the cost of larger file size. Useful for high Q factors. 
 *
 * If @trellis_quant is set and the version of libjpeg supports it
 * (e.g. mozjpeg >= 3.0), apply trellis quantisation to each 8x8 block.
 * Reduces file size but increases compression time.
 *
 * If @overshoot_deringing is set and the version of libjpeg supports it
 * (e.g. mozjpeg >= 3.0), apply overshooting to samples with extreme values
 * for example 0 and 255 for 8-bit. Overshooting may reduce ringing artifacts
 * from compression, in particular in areas where black text appears on a
 * white background.
 *
 * If @optimize_scans is set and the version of libjpeg supports it
 * (e.g. mozjpeg >= 3.0), split the spectrum of DCT coefficients into
 * separate scans. Reduces file size but increases compression time.
 *
 * If @quant_table is set and the version of libjpeg supports it
 * (e.g. mozjpeg >= 3.0) it selects the quantization table to use:
 *
 * * 0 — Tables from JPEG Annex K (vips and libjpeg default)
 * * 1 — Flat table
 * * 2 — Table tuned for MSSIM on Kodak image set
 * * 3 — Table from ImageMagick by N. Robidoux (current mozjpeg default)
 * * 4 — Table tuned for PSNR-HVS-M on Kodak image set
 * * 5 — Table from Relevance of Human Vision to JPEG-DCT Compression (1992)
 * * 6 — Table from DCTune Perceptual Optimization of Compressed Dental 
 *   X-Rays (1997)
 * * 7 — Table from A Visual Detection Model for DCT Coefficient 
 *   Quantization (1993)
 * * 8 — Table from An Improved Detection Model for DCT Coefficient 
 *   Quantization (1993)
 *
 * Quantization table 0 is the default in vips and libjpeg(-turbo), but it
 * tends to favor detail over color accuracy, producting colored patches and
 * stripes as well as heavy banding in flat areas at high compression ratios.
 * Quantization table 2 is a good candidate to try if the default quantization
 * table produces banding or color shifts and is well suited for hires images.
 * Quantization table 3 is the default in mozjpeg and has been tuned to produce
 * good results at the default quality setting; banding at high compression.
 * Quantization table 4 is the most accurate at the cost of compression ratio.
 * Tables 5-7 are based on older research papers, but generally achieve worse
 * compression ratios and/or quality than 2 or 4.
 *
 * The image is automatically converted to RGB, Monochrome or CMYK before 
 * saving. 
 *
 * EXIF data is constructed from #VIPS_META_EXIF_NAME, then
 * modified with any other related tags on the image before being written to
 * the file. #VIPS_META_RESOLUTION_UNIT is used to set the EXIF resolution
 * unit. #VIPS_META_ORIENTATION is used to set the EXIF orientation tag. 
 *
 * IPCT as #VIPS_META_IPCT_NAME and XMP as #VIPS_META_XMP_NAME
 * are coded and attached. 
 *
 * See also: vips_jpegsave_buffer(), vips_image_write_to_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_jpegsave( VipsImage *in, const char *filename, ... )
{
	va_list ap;
	int result;

	va_start( ap, filename );
	result = vips_call_split( "jpegsave", ap, in, filename );
	va_end( ap );

	return( result );
}

/**
 * vips_jpegsave_buffer:
 * @in: image to save 
 * @buf: return output buffer here
 * @len: return output length here
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @Q: JPEG quality factor
 * * @profile: attach this ICC profile
 * * @optimize_coding: compute optimal Huffman coding tables
 * * @interlace: write an interlaced (progressive) jpeg
 * * @strip: remove all metadata from image
 * * @no-subsample: disable chroma subsampling
 * * @trellis_quant: %gboolean, apply trellis quantisation to each 8x8 block
 * * @overshoot_deringing: %gboolean, overshoot samples with extreme values
 * * @optimize_scans: %gboolean, split DCT coefficients into separate scans
 * * @quant_table: %gint, quantization table index
 *
 * As vips_jpegsave(), but save to a memory buffer. 
 *
 * The address of the buffer is returned in @obuf, the length of the buffer in
 * @olen. You are responsible for freeing the buffer with g_free() when you
 * are done with it.
 *
 * See also: vips_jpegsave(), vips_image_write_to_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_jpegsave_buffer( VipsImage *in, void **buf, size_t *len, ... )
{
	va_list ap;
	VipsArea *area;
	int result;

	area = NULL; 

	va_start( ap, len );
	result = vips_call_split( "jpegsave_buffer", ap, in, &area );
	va_end( ap );

	if( !result &&
		area ) { 
		if( buf ) {
			*buf = area->data;
			area->free_fn = NULL;
		}
		if( len ) 
			*len = area->length;

		vips_area_unref( area );
	}

	return( result );
}

/**
 * vips_jpegsave_mime:
 * @in: image to save 
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @Q: JPEG quality factor
 * * @profile: attach this ICC profile
 * * @optimize_coding: compute optimal Huffman coding tables
 * * @strip: remove all metadata from image
 * * @no-subsample: disable chroma subsampling
 * * @trellis_quant: %gboolean, apply trellis quantisation to each 8x8 block
 * * @overshoot_deringing: %gboolean, overshoot samples with extreme values
 * * @optimize_scans: %gboolean, split DCT coefficients into separate scans
 * * @quant_table: %gint, quantization table index
 *
 * As vips_jpegsave(), but save as a mime jpeg on stdout.
 *
 * See also: vips_jpegsave(), vips_image_write_to_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_jpegsave_mime( VipsImage *in, ... )
{
	va_list ap;
	int result;

	va_start( ap, in );
	result = vips_call_split( "jpegsave_mime", ap, in );
	va_end( ap );

	return( result );
}
