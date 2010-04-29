/* Pass VIPS images through CImg
 *
 * JC, 15/10/07
 * 29/4/10
 * 	- oop, should be smalltile, probably
 * 	- tiny cleanups
 * 	- gtkdoc
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

#include <vips/vips.h>
#include <vips/internal.h>

/* CImg needs to call pthread directly, this is the preproc magic they
 * prefer.
 */
#if defined(sun)         || defined(__sun)      || defined(linux)       || defined(__linux) \
 || defined(__linux__)   || defined(__CYGWIN__) || defined(BSD)         || defined(__FreeBSD__) \
 || defined(__OPENBSD__) || defined(__MACOSX__) || defined(__APPLE__)   || defined(sgi) \
 || defined(__sgi)
  #include <pthread.h>
#endif

#include "CImg.h"
using namespace cimg_library;

/* Save params here.
 */
struct Greyc {
	IMAGE *in;
	IMAGE *out;
	IMAGE *mask;
	IMAGE **arry;

        int iterations;
	float amplitude; 
	float sharpness; 
	float anisotropy;
	float alpha; 
	float sigma; 
	float dl; 
	float da; 
	float gauss_prec; 
	int interpolation; 
	bool fast_approx;
};

// copy part of a vips region into a cimg
template<typename T> static CImg<T> *
vips_to_cimg( REGION *in, Rect *area )
{
	IMAGE *im = in->im;
	CImg<T> *img = new CImg<T>( area->width, area->height, 1, im->Bands );

	for( int y = 0; y < area->height; y++ ) {
		T *p = (T *) IM_REGION_ADDR( in, area->left, area->top + y );

		for( int x = 0; x < area->width; x++ ) {
			for( int z = 0; z < im->Bands; z++ )
				(*img)( x, y, z ) = p[z];

			p += im->Bands;
		}
	}

	return( img );
}

// write a CImg to a vips region
// fill out->valid, img has pixels in img_rect
template<typename T> static void 
cimg_to_vips( CImg<T> *img, Rect *img_rect, REGION *out )
{
	IMAGE *im = out->im;
	Rect *valid = &out->valid;

	g_assert( im_rect_includesrect( img_rect, valid ) );
	
	int x_off = valid->left - img_rect->left;
	int y_off = valid->top - img_rect->top;

	for( int y = 0; y < valid->height; y++ ) {
		T *p = (T *) IM_REGION_ADDR( out, valid->left, valid->top + y );

		for( int x = 0; x < valid->width; x++ ) {
			for( int z = 0; z < im->Bands; z++ )
				p[z] = static_cast<T>( (*img)( 
					x + x_off, y + y_off, z ) );

			p += im->Bands;
		}
	}
}

template<typename T> static int
greyc_gen( REGION *out, REGION **in, IMAGE **arry, Greyc *greyc )
{
	static const float gfact = (sizeof( T ) == 2) ? 1.0 / 256 : 1.0;
	static const int tile_border = 4;

	Rect *ir = &out->valid;
	Rect need;
	Rect image;

	CImg<T> *img;
	CImg<unsigned char> *msk;

	need = *ir;
	im_rect_marginadjust( &need, tile_border );
	image.left = 0;
	image.top = 0;
	image.width = in[0]->im->Xsize;
	image.height = in[0]->im->Ysize;
	im_rect_intersectrect( &need, &image, &need );
	if( im_prepare( in[0], &need ) )
		return( -1 );
	if( in[1] && im_prepare( in[1], &need ) )
		return( -1 );

	img = NULL;
	msk = NULL;

	try {
		img = vips_to_cimg<T>( in[0], &need );
		if( in[1] )
			msk = vips_to_cimg<unsigned char>( in[1], &need );
		else
			// empty mask
			msk = new CImg<unsigned char>();

		for( int i = 0; i < greyc->iterations; i++ ) 
			img->blur_anisotropic( *msk,
				greyc->amplitude, greyc->sharpness, 
				greyc->anisotropy,
				greyc->alpha, greyc->sigma, greyc->dl, 
				greyc->da, greyc->gauss_prec, 
				greyc->interpolation, greyc->fast_approx, 
				gfact );

		cimg_to_vips<T>( img, &need, out );
	}
	catch( CImgException e ) { 
		if( img )
			delete( img );
		if( msk )
			delete( msk );

		im_error( "GREYCstoration", "%s", e.message );

		return( -1 );
	}

	if( img )
		delete( img );
	if( msk )
		delete( msk );

	return( 0 );
}

// Hmm, strange double-cast needed
typedef int (*generate_fn)( REGION *out, REGION **in, 
	IMAGE **im, Greyc *greyc );

// as a plain C function
/**
 * im_greyc_mask:
 * @in: input image 
 * @out: output image
 * @mask: input mask 
 * @iterations: number of iterations to perform (eg. 1)
 * @amplitude: scaling factor (eg. 40)
 * @sharpness: degree of sharpening to apply (eg. 0.9)
 * @anisotropy: how much to blur along lines (eg. 0.15)
 * @alpha: blur by this much before calculating geometry (eg. 0.6)
 * @sigma: blur geometry by this much (eg. 1.1)
 * @dl: spatial integration step (eg. 0.8)
 * @da: angular integration step (eg. 30)
 * @gauss_prec: precision (eg. 2)
 * @interpolation: interpolation (eg. 0 for nearest-neighbour)
 *
 * This operation calls the blur_anisotropic() method of the CImag image
 * processing library. It is handy for denoising images and for upscaling.
 *
 * See also: im_conv().
 *
 * Returns: 0 on success, -1 on error
 */
int
im_greyc_mask( IMAGE *in, IMAGE *out, IMAGE *mask,
        int iterations,
	float amplitude, float sharpness, float anisotropy,
	float alpha, float sigma, 
	float dl, float da, float gauss_prec, 
	int interpolation, int fast_approx )
{
	IMAGE **arry;
	Greyc *greyc;

	if( im_piocheck( in, out ) ||
		im_check_uncoded( "im_greyc_mask", in ) ||
		im_check_u8or16orf( "im_greyc_mask", in ) )
		return( -1 );
	if( mask ) {
		if( im_pincheck( mask ) ||
			im_check_uncoded( "im_greyc_mask", mask ) ||
			im_check_size_same( "im_greyc_mask", in, mask ) ||
			im_check_format( "im_greyc_mask", 
				mask, IM_BANDFMT_UCHAR ) )
			return( -1 );
	}
	if( im_cp_desc( out, in ) ||
		!(arry = im_allocate_input_array( out, in, mask, NULL )) ||
		!(greyc = IM_NEW( out, Greyc )) ||
		im_demand_hint( out, IM_SMALLTILE, in, NULL ) )
		return( -1 );

	greyc->in = in;
	greyc->out = out;
	greyc->mask = mask;
	greyc->arry = arry;
	greyc->iterations = iterations;
	greyc->amplitude = amplitude;
	greyc->sharpness = sharpness;
	greyc->anisotropy = anisotropy;
	greyc->alpha = alpha;
	greyc->sigma = sigma;
	greyc->dl = dl;
	greyc->da = da;
	greyc->gauss_prec = gauss_prec;
	greyc->interpolation = interpolation;
	greyc->fast_approx = fast_approx;

	switch( in->BandFmt ) {
	case IM_BANDFMT_UCHAR:
	        if( im_generate( out, 
			im_start_many, 
			// double-cast to give g++ enough context to expand the
			// template correctly
			(im_generate_fn) (
				(generate_fn) greyc_gen<unsigned char>),
			im_stop_many, arry, greyc ) )
			return( -1 );
		break;

	case IM_BANDFMT_USHORT:
	        if( im_generate( out, 
			im_start_many, 
			(im_generate_fn) (
				(generate_fn) greyc_gen<unsigned short>),
			im_stop_many, arry, greyc ) )
			return( -1 );
		break;

	case IM_BANDFMT_FLOAT:
	        if( im_generate( out, 
			im_start_many, 
			(im_generate_fn) (
				(generate_fn) greyc_gen<float>),
			im_stop_many, arry, greyc ) )
			return( -1 );
		break;

	default:
		g_assert( 0 );
	}

	return( 0 );
}
