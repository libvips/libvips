/* rename.c --- wrappers for various renamed functions
 *
 * 20/9/09
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
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <string.h>

#include <vips/vips.h>
#include <vips/internal.h>

int 
im_remainderconst_vec( IMAGE *in, IMAGE *out, int n, double *c )
{
	return( im_remainder_vec( in, out, n, c ) );
}

int 
im_and_vec( IMAGE *in, IMAGE *out, int n, double *c )
{
	return( im_andimage_vec( in, out, n, c ) ); 
}

int 
im_or_vec( IMAGE *in, IMAGE *out, int n, double *c )
{
	return( im_orimage_vec( in, out, n, c ) ); 
}

int 
im_eor_vec( IMAGE *in, IMAGE *out, int n, double *c )
{
	return( im_eorimage_vec( in, out, n, c ) ); 
}

int 
im_andconst( IMAGE *in, IMAGE *out, double c )
{
	return( im_andimageconst( in, out, c ) ); 
}

int 
im_orconst( IMAGE *in, IMAGE *out, double c )
{
	return( im_orimageconst( in, out, c ) );
}

int 
im_eorconst( IMAGE *in, IMAGE *out, double c )
{
	return( im_eorimageconst( in, out, c ) );
}

void 
im_errormsg( const char *fmt, ... )
{	
	va_list ap;

	va_start( ap, fmt );
	im_verror( "untranslated", fmt, ap );
	va_end( ap );
}

void 
im_verrormsg( const char *fmt, va_list ap )
{	
	im_verror( "untranslated", fmt, ap );
}

void
im_errormsg_system( int err,  const char *fmt, ... )
{
	va_list ap;

	va_start( ap, fmt );
	im_verror_system( err, "untranslated", fmt, ap );
	va_end( ap );
}

void 
im_diagnostics( const char *fmt, ... )
{	
	va_list ap;

	va_start( ap, fmt );
	im_vdiag( "untranslated", fmt, ap );
	va_end( ap );
}

void 
im_warning( const char *fmt, ... )
{
	va_list ap;

	va_start( ap, fmt );
	im_vwarn( "untranslated", fmt, ap );
	va_end( ap );
}

int 
im_affine( IMAGE *in, IMAGE *out, 
	double a, double b, double c, double d, double dx, double dy, 
	int ox, int oy, int ow, int oh )
{
	return( im_affinei( in, out, 
		vips_interpolate_bilinear_static(), 
		a, b, c, d, dx, dy, 
		ox, oy, ow, oh ) );
}

int 
im_similarity_area( IMAGE *in, IMAGE *out, 
	double a, double b, double dx, double dy, 
	int ox, int oy, int ow, int oh )
{
	return( im_affinei( in, out, 
		vips_interpolate_bilinear_static(), 
		a, -b, b, a, dx, dy, 
		ox, oy, ow, oh ) );
}

int 
im_similarity( IMAGE *in, IMAGE *out, 
	double a, double b, double dx, double dy )
{
	return( im_affinei_all( in, out, 
		vips_interpolate_bilinear_static(), 
		a, -b, b, a, dx, dy ) ); 
}

DOUBLEMASK *
im_measure( IMAGE *im, IMAGE_BOX *box, int h, int v, 
	int *sel, int nsel, const char *name )
{
	return( im_measure_area( im,
		box->xstart,
		box->ystart,
		box->xsize,
		box->ysize,
		h, v, sel, nsel, name ) ); 
}

int
im_extract( IMAGE *in, IMAGE *out, IMAGE_BOX *box )
{	
	if( box->chsel == -1 )
		return( im_extract_areabands( in, out, 
			box->xstart, box->ystart, box->xsize, box->ysize,
			0, in->Bands ) );
	else
		return( im_extract_areabands( in, out, 
			box->xstart, box->ystart, box->xsize, box->ysize,
			box->chsel, 1 ) );
}

/* The public proto has this in the argument.
 */
typedef void (*notify_fn)( IMAGE *, Rect *, void * );

int
im_render_fade( IMAGE *in, IMAGE *out, IMAGE *mask, 
	int width, int height, int max, 
	int fps, int steps,
	int priority,
	notify_fn notify, void *client )
{
	return( im_render_priority( in, out, mask, 
		width, height, max, 
		priority,
		notify, client ) );
}

int
im_render( IMAGE *in, IMAGE *out, IMAGE *mask, 
	int width, int height, int max, 
	notify_fn notify, void *client )
{
	return( im_render_priority( in, out, mask, 
		width, height, max, 
		0, 
		notify, client ) );
}

int
im_makerw( IMAGE *im )
{
	return( im_rwcheck( im ) );
}

int
im_icc_export( IMAGE *in, IMAGE *out, 
	const char *output_profile_filename, int intent )
{ 
	return( im_icc_export_depth( in, out, 
		8, output_profile_filename, (VipsIntent) intent ) );
}

int 
im_segment( IMAGE *test, IMAGE *mask, int *segments )
{
	return( im_label_regions( test, mask, segments ) );
}

int 
im_convf( IMAGE *in, IMAGE *out, DOUBLEMASK *mask )
{
	return( im_conv_f( in, out, mask ) );
}

int
im_convf_raw( IMAGE *in, IMAGE *out, DOUBLEMASK *mask )
{
	return( im_conv_f_raw( in, out, mask ) );
}

int 
im_convsepf( IMAGE *in, IMAGE *out, DOUBLEMASK *mask )
{
	return( im_convsep_f( in, out, mask ) );
}

int
im_convsepf_raw( IMAGE *in, IMAGE *out, DOUBLEMASK *mask )
{
	return( im_convsep_f_raw( in, out, mask ) );
}

gboolean
im_isint( IMAGE *im )
{
	return( vips_bandfmt_isint( im->BandFmt ) );
}

gboolean
im_isuint( IMAGE *im )
{	
	return( vips_bandfmt_isuint( im->BandFmt ) );
}

gboolean
im_isfloat( IMAGE *im )
{
	return( vips_bandfmt_isfloat( im->BandFmt ) );
}

gboolean
im_iscomplex( IMAGE *im )
{	
	return( vips_bandfmt_iscomplex( im->BandFmt ) );
}

gboolean
im_isscalar( IMAGE *im )
{
	return( !im_iscomplex( im ) );
}

int 
im_c2ps( IMAGE *in, IMAGE *out )
{
	return( im_abs( in, out ) );
}

int
im_clip( IMAGE *in, IMAGE *out )
{
	return( im_clip2fmt( in, out, IM_BANDFMT_UCHAR ) );
}

int
im_clip2c( IMAGE *in, IMAGE *out )
{
	return( im_clip2fmt( in, out, IM_BANDFMT_CHAR ) );
}

int
im_clip2us( IMAGE *in, IMAGE *out )
{
	return( im_clip2fmt( in, out, IM_BANDFMT_USHORT ) );
}

int
im_clip2s( IMAGE *in, IMAGE *out )
{
	return( im_clip2fmt( in, out, IM_BANDFMT_SHORT ) );
}

int
im_clip2ui( IMAGE *in, IMAGE *out )
{
	return( im_clip2fmt( in, out, IM_BANDFMT_UINT ) );
}

int
im_clip2i( IMAGE *in, IMAGE *out )
{
	return( im_clip2fmt( in, out, IM_BANDFMT_INT ) );
}

int
im_clip2f( IMAGE *in, IMAGE *out )
{
	return( im_clip2fmt( in, out, IM_BANDFMT_FLOAT ) );
}

int
im_clip2d( IMAGE *in, IMAGE *out )
{
	return( im_clip2fmt( in, out, IM_BANDFMT_DOUBLE ) );
}

int
im_clip2cm( IMAGE *in, IMAGE *out )
{
	return( im_clip2fmt( in, out, IM_BANDFMT_COMPLEX ) );
}

int
im_clip2dcm( IMAGE *in, IMAGE *out )
{
	return( im_clip2fmt( in, out, IM_BANDFMT_DPCOMPLEX ) );
}

int
im_copy_from( IMAGE *in, IMAGE *out, im_arch_type architecture )
{
	switch( architecture ) {
	case IM_ARCH_NATIVE:
		return( im_copy( in, out ) );

	case IM_ARCH_BYTE_SWAPPED:
		return( im_copy_swap( in, out ) );

	case IM_ARCH_LSB_FIRST:
		return( im_amiMSBfirst() ? 
			im_copy_swap( in, out ) : im_copy( in, out ) );

	case IM_ARCH_MSB_FIRST:
		return( im_amiMSBfirst() ? 
			im_copy( in, out ) : im_copy_swap( in, out ) );

	default:
		im_error( "im_copy_from", 
			_( "bad architecture: %d" ), architecture );
		return( -1 );
	}
}

/* Check whether arch corresponds to native byte order.
 */
gboolean
im_isnative( im_arch_type arch )
{
	switch( arch ) {
	case IM_ARCH_NATIVE: 		
		return( TRUE );
	case IM_ARCH_BYTE_SWAPPED: 	
		return( FALSE );
	case IM_ARCH_LSB_FIRST: 	
		return( !im_amiMSBfirst() );
	case IM_ARCH_MSB_FIRST: 	
		return( im_amiMSBfirst() );

	default:
		g_assert( 0 );
	}  

	/* Keep -Wall happy.
	 */
	return( -1 );
}

int
im_iterate( IMAGE *im, 
	im_start_fn start, im_generate_fn generate, im_stop_fn stop,
	void *b, void *c )
{
	return( vips_sink( im, start, (VipsGenerateFn) generate, stop, b, c ) );
}

int
im_render_priority( IMAGE *in, IMAGE *out, IMAGE *mask, 
	int width, int height, int max, 
	int priority,
	notify_fn notify, void *client )
{
	return( vips_sink_screen( in, out, mask, 
		width, height, max, priority, notify, client ) ); 
}

/**
 * im_circle:
 * @im: image to draw on
 * @cx: centre of circle
 * @cy: centre of circle
 * @radius: circle radius
 * @intensity: value to draw
 *
 * Draws a circle on a 1-band 8-bit image. 
 *
 * This an inplace operation, so @im is changed. It does not thread and will
 * not work well as part of a pipeline. On 32-bit machines it will be limited
 * to 2GB images.
 *
 * See also: im_fastline().
 *
 * Returns: 0 on success, or -1 on error.
 */
int 
im_circle( IMAGE *im, int cx, int cy, int radius, int intensity )
{
	PEL ink[1];

	if( im_rwcheck( im ) ||
		im_check_uncoded( "im_circle", im ) ||
		im_check_mono( "im_circle", im ) ||
		im_check_format( "im_circle", im, IM_BANDFMT_UCHAR ) )
		return( -1 );

	ink[0] = intensity;

	return( im_draw_circle( im, cx, cy, radius, FALSE, ink ) );
}

/* A flood blob we can call from nip. Grr! Should be a way to wrap these
 * automatically. Maybe nip could do it if it sees a RW image argument?
 */

int
im_flood_copy( IMAGE *in, IMAGE *out, int x, int y, PEL *ink )
{
	IMAGE *t;

	if( !(t = im_open_local( out, "im_flood_blob_copy", "t" )) ||
		im_copy( in, t ) ||
		im_flood( t, x, y, ink, NULL ) ||
		im_copy( t, out ) ) 
		return( -1 );

	return( 0 );
}

int
im_flood_blob_copy( IMAGE *in, IMAGE *out, int x, int y, PEL *ink )
{
	IMAGE *t;

	if( !(t = im_open_local( out, "im_flood_blob_copy", "t" )) ||
		im_copy( in, t ) ||
		im_flood_blob( t, x, y, ink, NULL ) ||
		im_copy( t, out ) ) 
		return( -1 );

	return( 0 );
}

int
im_flood_other_copy( IMAGE *test, IMAGE *mark, IMAGE *out, 
	int x, int y, int serial )
{
	IMAGE *t;

	if( !(t = im_open_local( out, "im_flood_other_copy", "t" )) ||
		im_copy( mark, t ) ||
		im_flood_other( test, t, x, y, serial, NULL ) ||
		im_copy( t, out ) ) 
		return( -1 );

	return( 0 );
}

int
im_paintrect( IMAGE *im, Rect *r, PEL *ink )
{
	return( im_draw_rect( im, 
		r->left, r->top, r->width, r->height, 1, ink ) );
}

int
im_insertplace( IMAGE *main, IMAGE *sub, int x, int y )
{
	return( im_draw_image( main, sub, x, y ) );
}

int 
im_fastline( IMAGE *im, int x1, int y1, int x2, int y2, PEL *pel )
{
	return( im_draw_line( im, x1, y1, x2, y2, pel ) );
}

int 
im_fastlineuser( IMAGE *im, 
	int x1, int y1, int x2, int y2, 
	int (*fn)(), void *client1, void *client2, void *client3 )
{
	return( im_draw_line_user( im, x1, y1, x2, y2, 
		fn, client1, client2, client3 ) );
}

int
im_plotmask( IMAGE *im, int ix, int iy, PEL *ink, PEL *mask, Rect *r )
{
	IMAGE *mask_im;

	if( !(mask_im = im_image( mask, 
		r->width, r->height, 1, IM_BANDFMT_UCHAR )) )
		return( -1 );
	if( im_draw_mask( im, mask_im, ix + r->left, iy + r->top, ink ) ) {
		im_close( mask_im );
		return( -1 );
	}
	im_close( mask_im );

	return( 0 );
}

int 
im_readpoint( IMAGE *im, int x, int y, PEL *pel )
{
	return( im_read_point( im, x, y, pel ) );
}

int 
im_plotpoint( IMAGE *im, int x, int y, PEL *pel )
{
	return( im_draw_point( im, x, y, pel ) );
}

/* Smear a section of an IMAGE. As above, but shift it left a bit.
 */
int
im_smear( IMAGE *im, int ix, int iy, Rect *r )
{	
	int x, y, a, b, c;
	int ba = im->Bands;
	int el = ba * im->Xsize;
	Rect area, image, clipped;
	double total[ 256 ];

	if( im_rwcheck( im ) )
		return( -1 );

	/* Don't do the margins.
	 */
	area = *r;
	area.left += ix;
	area.top += iy;
	image.left = 0;
	image.top = 0;
	image.width = im->Xsize;
	image.height = im->Ysize;
	im_rect_marginadjust( &image, -1 );
	image.left--;
	im_rect_intersectrect( &area, &image, &clipped );

	/* Any left?
	 */
	if( im_rect_isempty( &clipped ) )
		return( 0 );

/* What we do for each type.
 */
#define SMEAR(TYPE) \
	for( y = clipped.top; y < clipped.top + clipped.height; y++ ) \
		for( x = clipped.left;  \
			x < clipped.left + clipped.width; x++ ) { \
			TYPE *to = (TYPE *) im->data + x * ba + y * el; \
			TYPE *from = to - el; \
			TYPE *f; \
 			\
			for( a = 0; a < ba; a++ ) \
				total[a] = 0.0; \
			\
			for( a = 0; a < 3; a++ ) { \
				f = from; \
				for( b = 0; b < 3; b++ ) \
					for( c = 0; c < ba; c++ ) \
						total[c] += *f++; \
				from += el; \
			} \
 			\
			for( a = 0; a < ba; a++ ) \
				to[a] = (40 * (double) to[a+ba] + total[a]) \
					/ 49.0; \
		}

	/* Loop through the remaining pixels.
	 */
	switch( im->BandFmt ) {
	case IM_BANDFMT_UCHAR: 
		SMEAR(unsigned char); 
		break; 

	case IM_BANDFMT_CHAR: 
		SMEAR(char); 
		break; 

	case IM_BANDFMT_USHORT: 
		SMEAR(unsigned short); 
		break; 

	case IM_BANDFMT_SHORT: 
		SMEAR(short); 
		break; 

	case IM_BANDFMT_UINT: 
		SMEAR(unsigned int); 
		break; 

	case IM_BANDFMT_INT: 
		SMEAR(int); 
		break; 

	case IM_BANDFMT_FLOAT: 
		SMEAR(float); 
		break; 

	case IM_BANDFMT_DOUBLE: 
		SMEAR(double); 
		break; 

	/* Do complex types too. Just treat as float and double, but with
	 * twice the number of bands.
	 */
	case IM_BANDFMT_COMPLEX:
		/* Twice number of bands: double size and bands.
		 */
		ba *= 2;
		el *= 2;

		SMEAR(float);

		break;

	case IM_BANDFMT_DPCOMPLEX:
		/* Twice number of bands: double size and bands.
		 */
		ba *= 2;
		el *= 2;

		SMEAR(double);

		break;

	default:
		im_error( "im_smear", "%s", _( "unknown band format" ) );
		return( -1 );
	}

	return( 0 );
}

int
im_smudge( VipsImage *image, int ix, int iy, Rect *r )
{
	return( im_draw_smudge( image, 
		r->left + ix, r->top + iy, r->width, r->height ) );
}

int 
im_flood( IMAGE *im, int x, int y, PEL *ink, Rect *dout )
{
	return( im_draw_flood( im, x, y, ink, dout ) );
}

int 
im_flood_blob( IMAGE *im, int x, int y, PEL *ink, Rect *dout )
{
	return( im_draw_flood_blob( im, x, y, ink, dout ) );
}

int 
im_flood_other( IMAGE *test, IMAGE *mark, 
	int x, int y, int serial, Rect *dout )
{
	return( im_draw_flood_other( mark, test, x, y, serial, dout ) );
}

