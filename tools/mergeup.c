/* Join together images 
 *
 * 	mergeup x y file_name output_dir <root>.0x0.v <root>.0x1.v ...
 *
 * Where the image has been take with patches named as
 *	
 *	.		.
 *	.		.
 *	<root>.0x1.v	<root>.1x1.v	..
 *	<root>.0x0.v	<root>.1x0.v	..
 *
 *
 * Tries to generate optimal join sequence. Does not require any intermidiate
 * files for temporary storage.
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
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
    02110-1301  USA

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
#include <locale.h>

#include <vips/vips.h>

#define NUM_FILES 1000
#define MAXPOINTS 60

static int xoverlap;
static int yoverlap;

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


static int 
im_phmerge( Rect *larea, Rect *rarea, Rect *outarea )
{	

	Rect overlap;


	/* Compute overlap.
	 */
	im_rect_intersectrect( larea, rarea, &overlap );

	outarea->width = rarea->left + rarea->width;
	outarea->height = overlap.height;
	outarea->top = overlap.top;
	outarea->left = larea->left;

	return( 0 );
}


static int 
im_pvmerge( Rect *tarea, Rect *barea, Rect *outarea )
{       

	Rect overlap;

	
	/* Compute overlap.
	 */
	im_rect_intersectrect( tarea, barea, &overlap );

	outarea->width = overlap.width;
	outarea->height = barea->top + barea->height ;
	outarea->left = overlap.left;
	outarea->top = tarea->top;

	return( 0 );
}




static int
merge_analysis(int width,int height,IMAGE **in,int xoff,
		int yoff,int *vxdisp,int *vydisp,int *hxdisp,
		int *hydisp,Rect *hrect,Rect *vrect)
{
int i,j;
int curr_im,offset;
int curr_x, curr_y;
Rect larea, rarea, barea;


 
	curr_im = -1;
	curr_x = -1;
	curr_y = -1;
	for(i=0; i<=height; i++){
      		for(j=0; j<=width; j++){
               		++curr_im;
			if( width == 0 ){
				++curr_x;
				hrect[curr_x].width = in[curr_im]->Xsize;
				hrect[curr_x].height= in[curr_im]->Ysize;
				hrect[curr_x].top = 0;
				hrect[curr_x].left = 0;
			}
			else{
			if( j == 0){
				++curr_x;

				/* Area occupied by left image.
	 			*/
				larea.left = 0;
				larea.top = 0;
				larea.height = in[curr_im]->Ysize;
				larea.width = in[curr_im]->Xsize;
				/* Area occupied by right image.
	 			*/
				if( in[curr_im]->Xsize < xoff ) 
					offset = 0;
				else
					offset =xoff;
				rarea.left = in[curr_im]->Xsize - (offset + hxdisp[curr_x]) ;
				rarea.top = hydisp[curr_x];
				rarea.width = in[curr_im+1]->Xsize;
				rarea.height = in[curr_im+1]->Ysize;
				im_phmerge( &larea, &rarea, &hrect[curr_x] );
			}
                	else if( j < width ){
                       		++curr_x;
	
				/* Area occupied by right image.
       	                	*/
				if( in[curr_im+1]->Xsize < xoff ) 
                                        offset = 0;
                                else
                                        offset =xoff;

                        	rarea.left = hrect[curr_x -1].width - (offset + hxdisp[curr_x]) ;
                        	rarea.top = hydisp[curr_x];
                        	rarea.width = in[curr_im+1]->Xsize;
                        	rarea.height = in[curr_im+1]->Ysize;
                        	im_phmerge( &hrect[curr_x -1], &rarea, &hrect[curr_x] );
                	}
			}
		}
                if( i > 0 ){
			++curr_y;

			/* Area occupied by bottom image in output.
	 		*/
			barea.left = vxdisp[curr_y];
			barea.width = hrect[curr_x].width;
			barea.height = hrect[curr_x].height;
			if( in[curr_x - width]->Ysize < yoff )
				offset = 0;
			else
				offset = yoff;
 			if( i == 1){
				barea.top = hrect[curr_x - width].height - offset - vydisp[curr_y] ;
				im_pvmerge( &hrect[curr_x - width], &barea, &vrect[curr_y] );
			}
			else{
				barea.top = vrect[curr_y - 1].height - yoff - vydisp[curr_y] ;
				im_pvmerge( &vrect[curr_y -1], &barea, &vrect[curr_y] );
			}
                }
        }


	return( 0 );
}

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
		im_error( "find_mosaic",
			 _( "bad file name format '%s'" ), name );
		free( out );
		return( NULL );
	}
	*p = '\0';

	/* Chop off nxn.
	 */
	if( !(p = strrchr( out, '.' )) ) {
		im_error( "find_mosaic",
			 _( "bad file name format '%s'" ), name );
		free( out );
		return( NULL );
	}
	*p = '\0';

	return( out );
}

/* Find the x position of a file name (extract n from <root>.nxm.v).
 */
static int
find_x( char *name )
{
	int n;
	char *p;
	char *out;

	out = strdup( name );

	/* Chop off '.v'.
	 */
	if( !(p = strrchr( out, '.' )) ) {
		im_error( "find_mosaic",
			 _( "bad file name format '%s'" ), name );
		free( out );
		return( -1 );
	}
	*p = '\0';

	/* Find '.nxm'.
	 */
	if( !(p = strrchr( out, '.' )) ) {
		im_error( "find_mosaic",
			 _( "bad file name format '%s'" ), name );
		free( out );
		return( -1 );
	}

	/* Read out x posn.
	 */
	if( sscanf( p, ".%dx%*d", &n ) != 1 ) {
		im_error( "find_mosaic",
			 _( "bad file name format '%s'" ), name );
		free( out );
		return( -1 );
	}

	free( out );

	return( n );
}

/* Find the y position of a file name (extract m from <root>.nxm.v).
 */
static int
find_y( char *name )
{
	int m;
	char *p;
	char *out;

	out = strdup( name );

	/* Chop off '.v'.
	 */
	if( !(p = strrchr( out, '.' )) ) {
		im_error( "find_mosaic",
			 _( "bad file name format '%s'" ), name );
		free( out );
		return( -1 );
	}
	*p = '\0';

	/* Find '.nxm'.
	 */
	if( !(p = strrchr( out, '.' )) ) {
		im_error( "find_mosaic",
			 _( "bad file name format '%s'" ), name );
		free( out );
		return( -1 );
	}

	/* Read out y posn.
	 */
	if( sscanf( p, ".%*dx%d", &m ) != 1 ) {
		im_error( "find_mosaic",
			 _( "bad file name format '%s'" ), name );
		free( out );
		return( -1 );
	}

	free( out );

	return( m );
}

/* Join two frames left-right. Have to open them and find their sizes.
 */
static int
join_leftright(IMAGE *left, IMAGE *right, IMAGE *out, int dx, int dy )
{
 
	if (im_lrmerge(left, right, out, dx, dy, 20) == -1)
            return( -1 );
return( 0 );
} 


/* Join two frames up-down. Have to open them and find their sizes.
*/
static int
join_updown( IMAGE *top, IMAGE *bottom, IMAGE *out, int dx, int dy )
{
	if (im_tbmerge(top, bottom, out, dx, dy, 20) == -1)
		return( -1 );

return( 0 );
}


static int
merge_up( int width, int height, IMAGE **inp, IMAGE *outp, int xoff, int yoff,
	      int *hxdisp, int *hydisp, Rect *vrect )
{
	int dx,dy,first_row;
	int i, j, partial_no, in_no;
	IMAGE **p_img;
	char name[29];
	int v_no, h_no;



	p_img = (IMAGE **) malloc(1 + 3 * width * height * sizeof(IMAGE *));
	if( p_img == NULL ){
	    im_error( "mergeup", "%s", _( "allocation failure in mergeup") );
	    return( -1 );
	}
	partial_no = 0;
	v_no = 0;
	h_no = 0;
	in_no = 0;
	first_row = 0;

	if( (width == 0 ) && (height == 0 ) ){
		im_error( "mergeup", "%s", _( "Need more than one image") );
		return( -1 );
	}


	for(i=0; i<=height; i++){
	    for(j=0; j<=width; j++){
		p_img[partial_no] = inp[in_no];
		++partial_no;
		if( j != 0 ){
		    im_snprintf( name, 29, "partial_img.%d.v",partial_no );
		    if( !( p_img[partial_no] = im_open( name, "p" )) ){
			free(p_img);
			return( -1 );
		    }
		    ++partial_no;
		    dy = hydisp[h_no ] ;
		    dx = -p_img[partial_no-3]->Xsize + hxdisp[h_no] + xoff ;

		    if( (height == 0) && ( j == width) )
			join_leftright( p_img[partial_no-3], 
					p_img[partial_no-2],outp,dx,dy );
		    else
		        join_leftright( p_img[partial_no-3], 
					p_img[partial_no-2],p_img[partial_no-1],dx,dy );
		    ++h_no;
		}
		++in_no;
	    }

	if( first_row == 0)
		first_row = partial_no - 1;

      if( ( i > 0 ) || ( height == 0) ){
             if( i < height ){
                im_snprintf( name, 29, "partial_img.%d.v", partial_no );
                if( !( p_img[partial_no] = im_open( name, "p" )) ){
			free(p_img);                       
                    	return( -1 );
                }
                ++partial_no;
		 
		 dy = -( vrect[v_no].height - p_img[partial_no-2]->Ysize ); 
		 dx = vrect[v_no].left ;

		 ++v_no;
	         join_updown( p_img[first_row], 
			      p_img[partial_no-2], p_img[partial_no-1],dx,dy );
		  first_row = partial_no-1;
              }
              else{
		dy = -( vrect[v_no].height - p_img[partial_no-1]->Ysize );
		dx = vrect[v_no].left ;

              	join_updown( p_img[first_row], p_img[partial_no-1],outp,dx,dy );
            }
	    }
        }
return( 0 );
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
	Rect hrect[NUM_FILES];
	Rect vrect[NUM_FILES];

	if( im_init_world( argv[0] ) )
	        error_exit( "unable to start VIPS" );
	textdomain( GETTEXT_PACKAGE );
	setlocale( LC_ALL, "" );

	/* Too many?
	 */
	if( argc > NUM_FILES + 1 )
		error_exit( "Too many files to merge" );
        for(i=0; i< NUM_FILES; i++)
           file_list[i] = 0;
	/* Too few?
	 */
	if( argc == 1 )
		error_exit( "usage: xoverlap yoverlap  file_name output_dir "
			"<root>.0x0.v <root>.0x1.v ..." );
	xoverlap = atoi(argv[1]);
	yoverlap = atoi(argv[2]);
	fp = fopen( argv[3] , "r" );

	for( i = 5; i < argc; i++ ){
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
	im_snprintf( name, 1000, "%s/paint.hr.v", argv[4] );
        if( !(out = im_open( name, "w" )) )
            error_exit("unable to open file for output");

	file_ptr =0;
        for(i=height; i>=0; i--)
            for(j=0; j<file_list[i]; j++){
                im_snprintf( name, 1000, "%s.%dx%d.v", file_root,j,i );
                output_file = strdup( name );
                if( !(in[file_ptr] = im_open( output_file, "r" )) )
                    error_exit("unable to open %s for input",output_file);
                ++file_ptr;

            }

	k = 0;
	for( i=0; i<height; i++ ){
		for( j=0; j<width; j++ ){
			if(fscanf(fp,"%d %d ", &hxdisp[k] , &hydisp[k])!=2)
				error_exit("argh");
			k++;
		}
		if(fscanf(fp,"\n")!=0)
			error_exit("argh3");
	}

	for( i=0; i<height; i++ )
		if(fscanf(fp,"%d %d\n", &vxdisp[i] , &vydisp[i])!=2)
			error_exit("argh2");

	merge_analysis(width,height,in,xoverlap,yoverlap,vxdisp,vydisp,hxdisp,hydisp,hrect,vrect);
	merge_up( width, height, in, out, xoverlap, yoverlap, hxdisp, hydisp, vrect );

	for(i=0; i<file_ptr; i++)
		if( im_close(in[i]) == -1)
			error_exit("unable to close partial file");  
		if( im_close(out) == -1)
			error_exit("unable to close\n ");

	vips_shutdown();

	return( 0 );
}
