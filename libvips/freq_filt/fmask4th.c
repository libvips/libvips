/* @(#) Typical filter functions
 * @(#)  va_list is flag, filter parameters 
 * @(#)   The following masks are implemented in this file
 * @(#)  lowpass highpass filters
 * @(#)  flag filter shape parameters
 * @(#)  0 -\> idealhpf, parameters: frequency cutoff
 * @(#)  1 -\> ideallpf, parameters: frequency cutoff
 * @(#)  2 -\> buthpf, parameters: order, frequency cutoff, amplitude cutoff
 * @(#)  3 -\> butlpf, parameters: order, frequency cutoff, amplitude cutoff
 * @(#)  4 -\> gaussianlpf, parameters: frequency cutoff, amplitude cutoff
 * @(#)  5 -\> gaussianhpf, parameters: frequency cutoff, amplitude cutoff
 * @(#)  ring pass ring reject filters
 * @(#)  6 -\> idealrpf, parameters: frequency cutoff, width
 * @(#)  7 -\> idealrrf, parameters: frequency cutoff, width
 * @(#)  8 -\> butrpf, parameters: order, freq cutoff, width, ampl cutoff
 * @(#)  9 -\> butrrf, parameters: order, freq cutoff, width, ampl cutoff
 * @(#)  10 -\> gaussianrpf, parameters: frequency cutoff, width, ampl cutoff
 * @(#)  11 -\> gaussianrrf, parameters: frequency cutoff, width, ampl cutoff
 * @(#)  fractal filters (for filtering gaussian noises only)
 * @(#)  18 -> fractal, parameters: fractal dimension
 * @(#)
 * @(#) Initially one forth of the coefficients is created and it is copied over
 * @(#) the four quadrants for faster processing
 * @(#)
 * @(#) Functions in this file; for explanations see each function
 * @(#)
 * @(#) float *
 * @(#) im__create_quarter( out, xs, ys, flag, ap )
 * @(#) IMAGE *out;
 * @(#) int xs, ys;
 * @(#) enum mask_type flag;
 * @(#) va_list ap;
 * @(#)
 *
 * Written on: Nov 1991
 * Updated on: Dec 1991
 * 20/9/95 JC
 *	- modernised
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

#include <stdio.h>
#include <math.h>
#include <stdarg.h>

#include <vips/vips.h>

/************************************************************************/
/* malloc space and create normalised coefficients accross		*/
/* the x (horizontal) and y (vertical) direction.			*/
/************************************************************************/
static int 
alloc( IMAGE *out, int xs, int ys, double **xd, double **yd, float **coeff )
{
	int i;
	double *x, *y;
	float *c;

	x = IM_ARRAY( out, xs/2 + 1, double );
	y = IM_ARRAY( out, ys/2 + 1, double );
	c = IM_ARRAY( out, (xs/2 + 1)*(ys/2 + 1), float );
	if( !x || !y || !c )
		return( -1 );

	for( i = 0; i < ys/2 + 1; i++ )
		y[i] = (i * i) / ((double) (ys*ys/4));
	for( i = 0; i < xs/2 + 1; i++ )
		x[i] = (i * i) / ((double) (xs*xs/4));
	*xd = x; *yd = y; *coeff = c;

	return( 0 );
}

/* xs and ys are the sizes of the final mask; all functions returns
 * the coefficients for one forth of the final mask
 */

/************************************************************************/
/* FLAG = 0								*/
/* Creates an ideal high pass filter mask				*/
/************************************************************************/
static float *
ideal_hpf( IMAGE *out, int xs, int ys, double fc )
{
	int x, y;
	float *coeff, *cpcoeff;
	double *xd, *yd, fc2, distance2;

	if( xs != ys || fc < 0.0 ) { 
		im_error( "ideal_hpf", "%s", _( "bad args" ) ); 
		return( NULL ); 
	}

	if( fc > 1.0 && fc <= xs/2 )
		fc2 = fc * fc * 4.0 / (double)(xs * ys);
	else if( fc <= 1.0 && fc > 0.0 )
		fc2 = fc * fc;
	else { 
		im_error( "ideal_hpf", "%s", _( "bad args" ) ); 
		return( NULL ); 
	}

	if( alloc( out, xs, ys, &xd, &yd, &coeff ) )
		return( NULL );

	cpcoeff = coeff;
        for( y = 0; y < ys/2 + 1; y++ )
                for( x = 0; x < xs/2 + 1; x++ ) {
                        distance2 = xd[x] + yd[y];
                        if( distance2 > fc2 )
                                *cpcoeff++ = 1.0;
                        else
                                *cpcoeff++ = 0.0;
		}	

	*coeff = 1.0;

	return( coeff );
}

/************************************************************************/
/* FLAG = 1								*/
/* Creates an ideal low pass filter mask				*/
/************************************************************************/
static float *
ideal_lpf( IMAGE *out, int xs, int ys, double fc )
{
	int x, y;
	float *coeff, *cpcoeff;
	double *xd, *yd, fc2, distance2;

	if( xs != ys || fc <= 0.0 ) { 
		im_error( "ideal_lpf", "%s", _( "bad args" ) ); 
		return( NULL ); 
	}

	if( fc > 1.0 && fc <= xs/2 )
		fc2 = fc * fc * 4.0 / (double)(xs * ys);
	else if( fc <= 1.0 && fc > 0.0 )
		fc2 = fc * fc;
	else { 
		im_error( "ideal_lpf", "%s", _( "bad args" ) ); 
		return( NULL );
	}

	if( alloc( out, xs, ys, &xd, &yd, &coeff ) )
		return( NULL );

	cpcoeff = coeff;
        for( y = 0; y < ys/2 + 1; y++ )
                for( x = 0; x < xs/2 + 1; x++ ) {
                        distance2 = xd[x] + yd[y];
                        if( distance2 <= fc2 )
                                *cpcoeff++ = 1.0;
                        else
                                *cpcoeff++ = 0.0;
		}	

	return( coeff );
}

/************************************************************************/
/* FLAG = 2								*/
/* Creates an Butterworth high pass filter mask				*/
/************************************************************************/
static float *
butterworth_hpf( IMAGE *out, int xs, int ys, 
	double order, double fc, double ac )
{
	int x, y;
	float *coeff, *cpcoeff;
	double *xd, *yd, fc2, distance2, cnst;

	if( xs != ys || fc < 0.0 || order < 1.0 || ac <= 0.0 || ac >= 1.0 ) {
		im_error( "butterworth_hpf", "%s", _( "bad args" ) );
		return( NULL );
	}

	if( fc > 1.0 && fc <= xs/2 )
		fc2 = fc * fc * 4.0 / (double)(xs * ys);
	else if( fc <= 1.0 && fc > 0.0 )
		fc2 = fc * fc;
	else {
		im_error( "butterworth_hpf", "%s", _( "bad args" ) );
		return( NULL );
	}

	if( alloc( out, xs, ys, &xd, &yd, &coeff) )
		return( NULL );

	cpcoeff = coeff;
	cnst = (1.0 / ac) - 1.0;
        for( y = 0; y < ys/2 + 1; y++ )
                for( x = 0; x < xs/2 + 1; x++ ) { 
			/* Leave the dc component unaltered 
			 */
			if( x == 0 && y == 0 )
				*cpcoeff++ = 1.0;
			else {
				distance2 = fc2 / (xd[x] + yd[y]);
                                *cpcoeff++ = 1.0 /
					(1.0 + cnst * pow( distance2, order ));
			}
		}	

	return( coeff );
}

/************************************************************************/
/* FLAG = 3								*/
/* Creates an Butterworth low pass filter mask				*/
/************************************************************************/
static float *
butterworth_lpf( IMAGE *out, int xs, int ys, 
	double order, double fc, double ac )
{
	int x, y;
	float *coeff, *cpcoeff;
	double *xd, *yd, fc2, distance2, cnst;

	if( xs != ys || fc <= 0.0 || order < 1.0 || ac >= 1.0 || ac <= 0.0 ) {
		im_error( "butterworth_lpf", "%s", _( "bad args" ) );
		return( NULL );
	}

	if( fc > 1.0 && fc <= xs/2 )
		fc2 = fc * fc * 4.0 / (double)(xs * ys);
	else if( fc <= 1.0 && fc > 0.0 )
		fc2 = fc * fc;
	else {
		im_error( "butterworth_lpf", "%s", _( "bad args" ) );
		return( NULL );
	}

	if( alloc( out, xs, ys, &xd, &yd, &coeff ) )
		return( NULL );

	cpcoeff = coeff;
	cnst = (1.0/ac) - 1.0;
        for( y = 0; y < ys/2 + 1; y++ )
		for( x = 0; x < xs/2 + 1; x++ ) {
			distance2 = (xd[x] + yd[y])/fc2;
			*cpcoeff++ = 1.0 / 
				(1.0 + cnst * pow( distance2, order ));
		}

	return( coeff );
}

/************************************************************************/
/* FLAG = 4								*/
/* Creates a gaussian high pass filter mask				*/
/************************************************************************/
static float *
gaussian_hpf( IMAGE *out, int xs, int ys, double fc, double ac )
{
	int x, y;
	float *coeff, *cpcoeff;
	double *xd, *yd, fc2, distance2, cnst;

	if( xs != ys || fc <= 0.0 || ac >= 1.0 || ac <= 0.0 ) {
		im_error( "gaussian_hpf", "%s", _( "bad args" ) );
		return( NULL );
	}

	if( fc > 1.0 && fc <= xs/2 )
		fc2 = fc * fc * 4.0 / (double)(xs * ys);
	else if( fc <= 1.0 && fc > 0.0 )
		fc2 = fc * fc;
	else {
		im_error( "gaussian_hpf", "%s", _( "bad args" ) );
		return( NULL );
	}

        if( alloc( out, xs, ys, &xd, &yd, &coeff ) )
                return( NULL );

	cpcoeff = coeff;
	cnst = -log( ac );
        for( y = 0; y < ys/2 + 1; y++ )
		for( x = 0; x < xs/2 + 1; x++ ) {
			distance2 = (xd[x] + yd[y])/fc2;
			*cpcoeff++ = 1.0 - exp( -cnst * distance2 );
		}	

	*coeff = 1.0;

	return( coeff );
}

/************************************************************************/
/* FLAG = 5								*/
/* Creates a gaussian low pass filter mask				*/
/************************************************************************/
static float *
gaussian_lpf( IMAGE *out, int xs, int ys, double fc, double ac )
{
	int x, y;
	float *coeff, *cpcoeff;
	double *xd, *yd, fc2, distance2, cnst;

	if( xs != ys || fc < 0.0 || ac >= 1.0 || ac <= 0.0 ) {
		im_error( "gaussian_lpf", "%s", _( "bad args" ) );
		return( NULL );
	}

	if( fc > 1.0 && fc <= xs/2 )
		fc2 = fc * fc * 4.0 / (double)(xs * ys);
	else if( fc <= 1.0 && fc > 0.0 )
		fc2 = fc * fc;
	else {
		im_error( "gaussian_lpf", "%s", _( "bad args" ) );
		return( NULL );
	}

        if( alloc( out, xs, ys, &xd, &yd, &coeff ) )
                return( NULL );

	cpcoeff = coeff;
	cnst = -log( ac );
	for( y = 0; y < ys/2 + 1; y++ )
		for( x = 0; x < xs/2 + 1; x++ ) {
			distance2 = (xd[x] + yd[y])/fc2;
			*cpcoeff++ =  exp( - cnst * distance2 );
		}	

	return( coeff );
}

/************************************************************************/
/* FLAG = 6								*/
/* Creates an ideal ring pass filter mask				*/
/* The band is a RING of internal radius fc-df and external radius fc+df*/
/************************************************************************/
static float *
ideal_rpf( IMAGE *out, int xs, int ys, double fc, double width )
{
	int x, y;
	float *coeff, *cpcoeff;
	double *xd, *yd, df, distance2, radius1_2, radius2_2;

	if( xs != ys || fc <= 0 || width <= 0 ) {
		im_error( "ideal_rpf", "%s", _( "bad args" ) );
		return( NULL );
	}

	df = width/2.0;
	if( fc <= 1.0 && df < 1.0 && fc - df > 0.0 ) { 
		radius1_2 = (fc-df)*(fc-df); 
		radius2_2 = (fc+df)*(fc+df); 
	}
	else if( fc - df > 1.0 && df >= 1.0 && fc <= xs/2 ) {
		radius1_2 = (fc - df) * (fc - df) * 4.0 / ((double)(xs * xs));
		radius2_2 = (fc + df) * (fc + df) * 4.0 / ((double)(xs * xs));
	}
	else {
		im_error( "ideal_rpf", "%s", _( "bad args" ) );
		return( NULL );
	}

        if( alloc( out, xs, ys, &xd, &yd, &coeff ) )
                return( NULL );

	cpcoeff = coeff;
	for( y = 0; y < ys/2 + 1; y++ )
		for( x = 0; x < xs/2 + 1; x++ ) {
                        distance2 = xd[x] + yd[y];
                        if( distance2 < radius2_2 && distance2 > radius1_2 )
                                *cpcoeff++ = 1.0;
                        else
                                *cpcoeff++ = 0.0;
		}	

	*coeff = 1.0;

	return( coeff );
}


/************************************************************************/
/* FLAG = 7								*/
/* Creates an ideal band reject filter mask				*/
/* The band is a RING of internal radius fc-df and external radius fc+df*/
/************************************************************************/
static float *
ideal_rrf( IMAGE *out, int xs, int ys, double fc, double width )
{
	int x, y;
	float *coeff, *cpcoeff;
	double *xd, *yd, df, distance2, radius1_2, radius2_2;

	if( xs != ys || fc < 0.0 || width <= 0.0 ) {
		im_error( "ideal_rrf", "%s", _( "bad args" ) );
		return( NULL );
	}

	df = width/2.0;
	if( fc <= 1.0 && df < 1.0 && fc - df > 0.0 ) { 
		radius1_2 = (fc-df)*(fc-df); 
		radius2_2 = (fc+df)*(fc+df); 
	}
	else if( fc - df > 1.0 && df >= 1.0 && fc <= xs/2 ) {
		radius1_2 = (fc - df) * (fc - df) * 4.0 / ((double)(xs * xs));
		radius2_2 = (fc + df) * (fc + df) * 4.0 / ((double)(xs * xs));
	}
	else {
		im_error( "ideal_rrf", "%s", _( "bad args" ) );
		return( NULL );
	}

	if( alloc( out, xs, ys, &xd, &yd, &coeff ) )
                return( NULL );

	cpcoeff = coeff;
	for( y = 0; y < ys/2 + 1; y++ )
		for( x = 0; x < xs/2 + 1; x++ ) {
                        distance2 = xd[x] + yd[y];
                        if( distance2 < radius2_2 && distance2 > radius1_2 )
                                *cpcoeff++ = 0.0;
                        else
                                *cpcoeff++ = 1.0;
		}	

	return( coeff );
}


/************************************************************************/
/* FLAG = 8								*/
/* Creates a butterworth band pass filter mask				*/
/* The band is a RING of internal radius fc-df and external radius fc+df*/
/************************************************************************/
static float *
butterworth_rpf( IMAGE *out, int xs, int ys, 
	double order, double fc, double width, double ac )
{
	int x, y;
	float *coeff, *cpcoeff;
	double *xd, *yd, d, df, ndf, ndf2, nfc, cnst;

	if( xs != ys || fc <= 0.0 || width <= 0.0 ||
	     order < 1.0 || ac >= 1.0 || ac <= 0.0 ) {
		im_error( "butterworth_rpf", "%s", _( "bad args" ) );
		return( NULL );
	}

	df = width/2.0;
	if( fc <= 1.0 && df < 1.0 && fc-df > 0.0 ) { 
		nfc = fc; 
		ndf = width/2.0; 
	}
	else if( fc - df > 1.0 && df >= 1.0 && fc <= xs/2 ) { 
		nfc = fc * 2.0 /(double)xs; 
		ndf = width /(double)ys; 
	}
	else {
		im_error( "butterworth_rpf", "%s", _( "bad args" ) );
		return( NULL );
	}

        if( alloc( out, xs, ys, &xd, &yd, &coeff ) )
                return( NULL );

	cpcoeff = coeff;
	cnst = (1.0/ac) - 1.0;
	ndf2 = ndf * ndf;
	for( y = 0; y < ys/2 + 1; y++ )
		for( x = 0; x < xs/2 + 1; x++ ) {
			d = sqrt( xd[x] + yd[y] );
			*cpcoeff++ = 1.0 /
				(1.0 + cnst * 
					pow( (d-nfc)*(d-nfc)/ndf2, order ));
		}	

	*coeff = 1.0;

	return( coeff );
}



/************************************************************************/
/* FLAG = 9								*/
/* Creates a butterworth ring reject filter mask			*/
/* The band is a RING of internal radius fc-df and external radius fc+df*/
/************************************************************************/
static float *
butterworth_rrf( IMAGE *out, int xs, int ys, 
	double order, double fc, double width, double ac )
{
	int x, y;
	float *coeff, *cpcoeff;
	double *xd, *yd, d, df, ndf, ndf2, nfc, cnst;

	if( xs != ys || fc <= 0.0 || width <= 0.0 ||
	     order < 1.0 || ac >= 1.0 || ac <= 0.0 ) {
		im_error( "butterworth_rrf", "%s", _( "bad args" ) );
		return( NULL );
	}

	df = width/2.0;
	if( fc <= 1.0 && df < 1.0 && fc-df > 0.0 ) { 
		nfc = fc; 
		ndf = width/2.0; 
	}
	else if( fc - df > 1.0 && df >= 1.0 && fc <= xs/2 ) { 
		nfc = fc * 2.0 /(double)xs; 
		ndf = width /(double)ys; 
	}
	else {
		im_error( "butterworth_rrf", "%s", _( "bad args" ) );
		return( NULL );
	}

        if( alloc( out, xs, ys, &xd, &yd, &coeff ) )
                return( NULL );

	cpcoeff = coeff;
	cnst = (1.0/ac) - 1.0;
	ndf2 = ndf * ndf;
	for( y = 0; y < ys/2 + 1; y++ )
		for( x = 0; x < xs/2 + 1; x++ ) {
			d = sqrt( xd[x] + yd[y] );
			if( d == 0.0 )
				*cpcoeff++ = 1.0;
			else
				*cpcoeff++ = 1.0 /
					(1.0 + cnst * pow( 
					ndf2/((d-nfc)*(d-nfc)), order ));
		}	

	return( coeff );
}

/************************************************************************/
/* FLAG = 10								*/
/* Creates a gaussian band pass filter mask				*/
/* The band is a RING of internal radius fc-df and external radius fc+df*/
/************************************************************************/
static float *
gaussian_rpf( IMAGE *out, int xs, int ys, double fc, double width, double ac )
{
	int x, y;
	float *coeff, *cpcoeff;
	double *xd, *yd, d, df, ndf, ndf2, nfc, cnst;

	if( xs != ys || fc < 0.0 || width <= 0.0 || ac <= 0.0 || ac > 1.0 ) {
		im_error( "gaussian_rpf", "%s", _( "bad args" ) );
		return( NULL );
	}

	df = width/2.0;
	if( fc <= 1.0 && df < 1.0 && fc - df > 0.0 ) { 
		nfc = fc; 
		ndf = width/2.0; 
	}
	else if( fc - df > 1.0 && df >= 1.0 && fc <= xs/2 ) { 
		nfc = fc * 2.0 /(double) xs; 
		ndf = width /(double)ys; 
	}
	else {
		im_error( "gaussian_rpf", "%s", _( "bad args" ) );
		return( NULL );
	}

        if( alloc( out, xs, ys, &xd, &yd, &coeff ) )
                return( NULL );

	cpcoeff = coeff;
	cnst = -log( ac );
	ndf2 = ndf * ndf;
	for( y = 0; y < ys/2 + 1; y++ )
		for( x = 0; x < xs/2 + 1; x++ ) {
			d = sqrt( xd[x] + yd[y] );
			*cpcoeff++ = exp( -cnst * (d-nfc) * (d-nfc)/ndf2 );
		}	

	*coeff = 1.0;

	return( coeff );
}




/************************************************************************/
/* FLAG = 11								*/
/* Creates a gaussian band reject filter mask				*/
/* The band is a RING of internal radius fc-df and external radius fc+df*/
/************************************************************************/
static float *
gaussian_rrf( IMAGE *out, int xs, int ys, double fc, double width, double ac )
{
	int x, y;
	float *coeff, *cpcoeff;
	double *xd, *yd, d, df, ndf, ndf2, nfc, cnst;

	if( xs != ys || fc < 0.0 || width <= 0.0 || ac <= 0.0 || ac > 1.0 ) {
		im_error( "gaussian_rrf", "%s", _( "bad args" ) );
		return( NULL );
	}

	df = width/2.0;
	if( fc <= 1.0 && df < 1.0 && fc - df > 0.0 ) { 
		nfc = fc; 
		ndf = width/2.0; 
	}
	else if( fc - df > 1.0 && df >= 1.0 && fc <= xs/2 ) { 
		nfc = fc * 2.0 /(double) xs; 
		ndf = width / (double)ys; 
	}
	else {
		im_error( "gaussian_rrf", "%s", _( "bad args" ) );
		return( NULL );
	}

        if( alloc( out, xs, ys, &xd, &yd, &coeff ) )
                return( NULL );

	cpcoeff = coeff;
	cnst = -log( ac );
	ndf2 = ndf * ndf;
	for( y = 0; y < ys/2 + 1; y++ )
		for( x = 0; x < xs/2 + 1; x++ ) {
			d = sqrt( xd[x] + yd[y] );
			*cpcoeff++ = 1.0 - 
				exp( -cnst * (d-nfc) * (d-nfc) / ndf2 );
		}	

	return( coeff );
}

/************************************************************************/
/* FLAG = 18								*/
/* Theoretically the power spectrum of a fractal surface should decay 
 * according to its fractal dimension
 *  This program should be used to create fractal images by filtering the
 * power spectrum of Gaussian white noise
 * More specifically according to PIET:
 * since the coefficients of fractal noise
 * < |vsubk|^2 > decay as 1/( |f|^(beta+1) )
 * or since beta=2*H + 1, beta= 7-2*D
 * < |vsubk|^2 > decay as 1/( |f|^(8-2*D) )
 * and the fractal filter which should produce vsubk
 * should have transfer function decaying as 1/( |f|^((beta+1)/2) )
 * where f = sqrt(fsubx * fsubx + fsuby *fsuby)
 * Finally the filter has transfer function decaying as
 * sqrt(fsubx*fsubx+fsuby*fsuby)^(D-4) or
 * (fsubx*fsubx+fsuby*fsuby)^((D-4)/2) <--- This relation is used.
 * On the other hand if D=3-H, the filtermask should decay as
 * (fsubx*fsubx+fsuby*fsuby)^(-(H+1)/2) , 0<H<1
 * which is exactly the same as above (PIET page 108)
 *  Please note that when a filter mask is created to dc coefficient is
 * set to 1.0 and therefore when a mask is scaled for display
 * the dc coefficient appears to be wrong (it is not!!)
 */
/************************************************************************/

static float *
fractal_flt( IMAGE *out, int xs, int ys, double frdim )
{
	int x, y;
	float *coeff, *cpcoeff;
	double *xd, *yd, distance2, cnst;

	if( xs != ys || frdim <= 2.0 || frdim >= 3.0 ) {
		im_error( "fractal_flt", "%s", _( "bad args" ) );
		return( NULL );
	}

        if( alloc( out, xs, ys, &xd, &yd, &coeff ) )
                return( NULL );

	cpcoeff = coeff;
	cnst = (frdim - 4.0)/2.0;
	for( y = 0; y < ys/2 + 1; y++ )
                for( x = 0; x < xs/2 + 1; x++ ) {
			distance2 = xd[x] + yd[y];
			if( distance2 == 0.0 )
				*cpcoeff++ = 1.0;
			else
				*cpcoeff++ = pow( distance2, cnst );
		}

	return( coeff );
}

/* Creates one forth of the mask coefficients.  If the final mask is
 * xsize by xsize, one forth should have sizes (xsize/2 + 1) by (ysize/2 + 1)
 *  This happens because the horizontal spatial frequencies extend
 * from -xsize/2 up to (xsize/2 - 1) inclusive and
 * the vertical spatial frequencies 
 * from -ysize/2  up to (ysize/2 - 1) inclusive
 *  In order to calculate the spatial frequencies at location (x, y)
 * the maximum spatial frequency at the horizontal direction xsize/2 and  
 * the maximum spatial frequency at the vertical direction ysize/2 have 
 * been normalised to 1.0.  
 * All arithmetic internally has been carried out in double precision;
 * however all masks are written as floats with maximum value normalised to 1.0
 */

float *
im__create_quarter( IMAGE *out, int xs, int ys, VipsMaskType flag, va_list ap )
{
	/* May be fewer than 4 args ... but extract them all anyway. Should be
	 * safe.
	 */
	double p0 = va_arg( ap, double );
	double p1 = va_arg( ap, double );
	double p2 = va_arg( ap, double );
	double p3 = va_arg( ap, double );

	switch( flag ) {
		/* High pass - low pass 
		 */
		case VIPS_MASK_IDEAL_HIGHPASS:
			return( ideal_hpf( out, xs, ys, p0 ) );

		case VIPS_MASK_IDEAL_LOWPASS:
			return( ideal_lpf( out, xs, ys, p0 ) );

		case VIPS_MASK_BUTTERWORTH_HIGHPASS:
			return( butterworth_hpf( out, xs, ys, p0, p1, p2 ) );

		case VIPS_MASK_BUTTERWORTH_LOWPASS:
			return( butterworth_lpf( out, xs, ys, p0, p1, p2 ) );

		case VIPS_MASK_GAUSS_HIGHPASS:
			return( gaussian_hpf( out, xs, ys, p0, p1 ) );

		case VIPS_MASK_GAUSS_LOWPASS:
			return( gaussian_lpf( out, xs, ys, p0, p1 ) );

		/* Ring pass - ring reject.
		 */
		case VIPS_MASK_IDEAL_RINGPASS:
			return( ideal_rpf( out, xs, ys, p0, p1 ) );

		case VIPS_MASK_IDEAL_RINGREJECT:
			return( ideal_rrf( out, xs, ys, p0, p1 ) );

		case VIPS_MASK_BUTTERWORTH_RINGPASS:
			return( butterworth_rpf( out, 
				xs, ys, p0, p1, p2, p3 ) );

		case VIPS_MASK_BUTTERWORTH_RINGREJECT:
			return( butterworth_rrf( out, 
				xs, ys, p0, p1, p2, p3 ) );

		case VIPS_MASK_GAUSS_RINGPASS:
			return( gaussian_rpf( out, xs, ys, p0, p1, p2 ) );

		case VIPS_MASK_GAUSS_RINGREJECT:
			return( gaussian_rrf( out, xs, ys, p0, p1, p2 ) );

		case VIPS_MASK_FRACTAL_FLT:
			return( fractal_flt( out, xs, ys, p0 ) );

		default:
			im_error( "create_quarter", "%s", 
				_( "unimplemented mask" ) );
			return( NULL );
	}

	/*NOTREACHED*/
}
