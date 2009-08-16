/* Join together images. 
 *
 * 	find_mosaic x y file_name <root>.0x0.v <root>.0x1.v ...
 *
 * Where the image has been take with patches named as
 *	
 *	.		.
 *	.		.
 *	<root>.0x1.v	<root>.1x1.v	..
 *	<root>.0x0.v	<root>.1x0.v	..
 *
 * Uses im__find_lroverlap and im__find_tboverlap routines to make <root>.v. 
 *
 * It stores the tie points between patches in a data_file. 
 *
 * It uses partials on all IO by including tbmerge / lrmerge programs.
 *
 *  
 * Copyright (C) Feb./1995,   Ahmed. Abbood
 * National Gallery. London
 *
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
#include <stdlib.h>
#include <stdarg.h>

#include <string.h>
#include <ctype.h>
#include <math.h>
#include <fcntl.h>

#include <vips/vips.h>

#define NUM_FILES 1000
#define MAXPOINTS 60
int xoverlap;
int yoverlap;

extern int im_lrmerge();
extern int im_merge_analysis();
extern int im__find_lroverlap();
extern int im__find_tboverlap();
static int file_ptr = 0;
static IMAGE *in[ NUM_FILES ];



/* Strategy: build a tree describing the sequence of joins we want. Walk the
 * tree assigning temporary file names, compile the tree into a linear
 * sequence of join commands.
 */



/* Decoded file name info.
 */
static char *file_root = NULL;
static char *output_file = NULL;
static int width = 0;		/* Number of frames across */
static int height = 0;		/* Number of frames down */

static int file_list[ NUM_FILES ];




/* Find the root name of a file name. Return new, shorter, string.
 */
static char *
find_root( name )
char *name;
{	char *out = strdup( name );
	char *p;

	/* Chop off '.v'.
	 */
	if( !(p = strrchr( out, '.' )) ) {
		im_errormsg( "Bad file name format '%s'", name );
		free( out );
		return( NULL );
	}
	*p = '\0';

	/* Chop off nxn.
	 */
	if( !(p = strrchr( out, '.' )) ) {
		im_errormsg( "Bad file name format '%s'", name );
		free( out );
		return( NULL );
	}
	*p = '\0';

	return( out );
}

/* Find the x position of a file name (extract n from <root>.nxm.v).
 */
static int
find_x( name )
char *name;
{	int n;
	char *p;
	char *out = strdup( name );

	/* Chop off '.v'.
	 */
	if( !(p = strrchr( out, '.' )) ) {
		im_errormsg( "Bad file name format '%s'", name );
		free( out );
		return( -1 );
	}
	*p = '\0';

	/* Find '.nxm'.
	 */
	if( !(p = strrchr( out, '.' )) ) {
		im_errormsg( "Bad file name format '%s'", name );
		free( out );
		return( -1 );
	}

	/* Read out x posn.
	 */
	if( sscanf( p, ".%dx%*d", &n ) != 1 ) {
		im_errormsg( "Bad file name format '%s'", name );
		free( out );
		return( -1 );
	}

	return( n );
}

/* Find the y position of a file name (extract m from <root>.nxm.v).
 */
static int
find_y( name )
char *name;
{	int m;
	char *p;
	char *out = strdup( name );

	/* Chop off '.v'.
	 */
	if( !(p = strrchr( out, '.' )) ) {
		im_errormsg( "Bad file name format '%s'", name );
		free( out );
		return( -1 );
	}
	*p = '\0';

	/* Find '.nxm'.
	 */
	if( !(p = strrchr( out, '.' )) ) {
		im_errormsg( "Bad file name format '%s'", name );
		free( out );
		return( -1 );
	}

	/* Read out y posn.
	 */
	if( sscanf( p, ".%*dx%d", &m ) != 1 ) {
		im_errormsg( "Bad file name format '%s'", name );
		free( out );
		return( -1 );
	}

	free( out );
	return( m );
}


 

static int
mosaic_analysis(int width, int height,IMAGE **inp, IMAGE *out, 
	int xoff, int yoff, int *vxdisp, int *vydisp,int *hxdisp, int *hydisp) {



int i, j, dx, dy, curr_im, fx, fy;
int halfcorsize, halfareasize;
int mincorsize, minareasize;
int prev_row, curr_row, curr_disp_x, curr_disp_y;
double scale1, angle1, dx1, dy1;

	
	curr_im = -1;
	curr_disp_x = -1;
	curr_disp_y = -1;
	dy = -1;
	for(i=0; i<=height; i++){
		for(j=0; j<=width; j++){
		++curr_im;
		halfcorsize = 5;
        	halfareasize = 14;
        	dx = xoff - inp[curr_im]->Xsize;
		dy = yoff - inp[curr_im]->Ysize;

		if( ( j < width ) && ( width > 0 ) ){
        		if( dx < 0 ){
                		mincorsize = (int)(inp[curr_im]->Xsize + dx - 1)/6;
                		minareasize = (int)(inp[curr_im]->Xsize + dx 
					      - 3*halfcorsize -1)/2 - mincorsize;
                		if(mincorsize > halfcorsize)
                        		mincorsize = halfcorsize;
                		if( minareasize > 0 ){
                  			if( minareasize < halfareasize ){
                    				if( minareasize > 
						    (int)(halfcorsize +(int)(halfcorsize/2 + 1))){
                        				halfareasize = minareasize;
                    				}
                    				else if(mincorsize > 2){
                         				halfcorsize=mincorsize;
                         				halfareasize=(int)(mincorsize+mincorsize/2 +1);
                    				}
                  			}
                		}
        		}

			if( ( inp[curr_im]->Xsize < xoff ) || ( inp[curr_im+1]->Xsize < xoff ) ||
			    ( inp[curr_im]->Ysize < yoff ) || ( inp[curr_im]->Ysize < yoff) ){
				++curr_disp_x;
				hxdisp[curr_disp_x] = 0;
				hydisp[curr_disp_x] = 0;
			}
			else{
        		if ( im__find_lroverlap(inp[curr_im], inp[curr_im+1],
				out, 0,
                	   	(int)(inp[curr_im]->Xsize -xoff/2), 
				(int)(inp[curr_im]->Ysize /2), 
				(int)(xoff/2), (int)(inp[curr_im+1]->Ysize /2),
                		halfcorsize, halfareasize , &fx, &fy,
				&scale1, &angle1, &dx1, &dy1 ) == -1 )
                		error_exit("Unable to im__find_lroverlap");

			++curr_disp_x;
			hxdisp[curr_disp_x] = inp[curr_im]->Xsize - xoff + fx;
			hydisp[curr_disp_x] = fy;
			}
		}
		}
		if( ( i < height ) && ( height > 0 ) ){
			curr_row = curr_im+1+(int)(width/2);
			prev_row = curr_im - width+(int)(width/2);
        		halfcorsize = 5;
        		halfareasize = 14;
 
        	      if( dy < 0){
                	mincorsize = (int)(inp[prev_row]->Ysize + dy - 1)/6;
                	minareasize = (int)(inp[prev_row]->Ysize + dy 
					- 3*halfcorsize -1)/2 - mincorsize;
                	if(mincorsize > halfcorsize)
                       		mincorsize = halfcorsize;
               		if( minareasize > 0 ){
				if( minareasize < halfareasize ){
					if( minareasize > 
				          (int)(halfcorsize +(int)(halfcorsize/2 + 1))){
						halfareasize = minareasize;
                  			}
                   			else if(mincorsize > 2){
                         			halfcorsize=mincorsize;
                         			halfareasize=(int)(mincorsize+mincorsize/2 +1);
                    			}
                  		}
                	}
        	     }
 		     if( ( inp[curr_row]->Xsize < xoff ) || ( inp[prev_row]->Xsize < xoff ) ||
			 ( inp[curr_row]->Ysize < yoff ) || ( inp[prev_row]->Ysize < yoff ) ){
				++curr_disp_y;
				vxdisp[curr_disp_y] = 0;
				vydisp[curr_disp_y] = 0;
		     }
		     else{
		     if ( im__find_tboverlap(inp[prev_row], inp[curr_row],
			     out, 0,
                	 	(int)(inp[prev_row]->Xsize/2 ), 
				(int)(inp[prev_row]->Ysize - yoff/2 ),
			 	(int)(inp[curr_row]->Xsize/2 ), (int)(yoff/2),
                	 	halfcorsize, halfareasize, &fx, &fy,
				&scale1, &angle1, &dx1, &dy1 ) == -1 )
                		error_exit("Unable to im__find_tboverlap");


		     ++curr_disp_y;
		     vxdisp[curr_disp_y] = fx;
		     vydisp[curr_disp_y] = inp[prev_row]->Ysize - yoff + fy;
		     }
		}
	}


	return ( 0 );
}



int
main( argc, argv )
int argc;
char **argv;
{
	int i, n, j, k;
	char name[ 1000 ];
	FILE *fp;
	char *r;
        IMAGE *out;
	int vxdisp[NUM_FILES + 1] ;
	int vydisp[NUM_FILES + 1] ;
	int hxdisp[NUM_FILES + 1] ;
	int hydisp[NUM_FILES + 1] ;

	if( im_init_world( argv[0] ) )
	        error_exit( "unable to start VIPS" );

	/* Too many?
	 */
	if( argc > NUM_FILES + 1 )
		error_exit( "Too many files to merge" );
        for(i=0; i< NUM_FILES; i++)
           file_list[i] = 0;
	/* Too few?
	 */
	if( argc == 1 )
		error_exit( "usage: xoverlap yoverlap  file_name "
			"<root>.0x0.v <root>.0x1.v ..." );
	xoverlap = atoi(argv[1]);
	yoverlap = atoi(argv[2]);
	fp = fopen( argv[3] , "w" );

	for( i = 4; i < argc; i++ ){
		/* Find/check root.
	 	*/
		if( !file_root ) {
			file_root = find_root( argv[i] );
			if( !file_root )
				error_exit( "error at file_root" );
		}
		else {
			if( !(r = find_root( argv[i] )) )
				error_exit( "Error in reading parameters" );
			if( strcmp( r, file_root ) != 0 )
				error_exit( "Not all roots identical!" );
		}

		/* Read out position.
		 */
		if( (n = find_x( argv[i] )) < 0 )
			error_exit( "Error in reading file name" );
		if( n > width - 1 )
			width = n;
		if( (n = find_y( argv[i] )) < 0 )
			error_exit( "Error in reading file name" );
		if( n > height - 1 )
			height = n;
	
       		file_list[n] +=1;
	 }	

	/* Make output name. and store them in an array.
	 */
        if( !(out = im_open( "tmp.v", "t" )) )
            error_exit("unable to open file for output");

	file_ptr =0;
        for(i=height; i>=0; i--)
            for(j=0; j<file_list[i]; j++){
                im_snprintf( name, 1024, "%s.%dx%d.v", file_root,j,i );
                output_file = strdup( name );
                if( !(in[file_ptr] = im_open( output_file, "r" )) )
                    error_exit("unable to open %s for input",output_file);
                ++file_ptr;

            }

	mosaic_analysis(width,height,in,out,xoverlap,yoverlap,vxdisp,vydisp,hxdisp,hydisp);
	k = 0;
	for( i=0; i<height; i++ ){
		for( j=0; j<width; j++ ){
			fprintf(fp,"%d %d ", hxdisp[k] , hydisp[k] );
			k++;
		}
		fprintf(fp,"\n");
	}

	for( i=0; i<height; i++ )
                fprintf(fp,"%d %d\n", vxdisp[i] , vydisp[i] );


	for(i=0; i<file_ptr; i++)
		if( im_close(in[i]) == -1)
			error_exit("unable to close partial file");  
		if( im_close(out) == -1)
			error_exit("unable to close\n ");
	fclose( fp );


	return( 0 );
}
