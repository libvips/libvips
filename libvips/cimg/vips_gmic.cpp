/* Pass VIPS images through gmic
 *
 * AF, 6/10/14
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

#include <vips/vips.h>
#include <vips/dispatch.h>

#include <limits.h>

#include <iostream>

/* CImg needs to call pthread directly, this is the preproc magic they
 * prefer.
#if defined(sun)         || defined(__sun)      || defined(linux)       || defined(__linux) \
  || defined(__linux__)   || defined(__CYGWIN__) || defined(BSD)         || defined(__FreeBSD__) \
  || defined(__OPENBSD__) || defined(__MACOSX__) || defined(__APPLE__)   || defined(sgi) \
  || defined(__sgi)
#include <pthread.h>
#endif
 */

#include "CImg.h"
#include "gmic.h"

using namespace cimg_library;

//#define gmic_image cimg_library::CImg


#define GMIC_MAX_INPUT_IMAGES 10

typedef struct _VipsGMic {
  VipsOperation parent_instance;
  VipsImage* in[GMIC_MAX_INPUT_IMAGES];
  int ninput;
  VipsImage* out;
  char* command;
  int padding;
  double x_scale;
  double y_scale;
} VipsGMic;

typedef VipsOperationClass VipsGMicClass;


#define VIPS_TYPE_GMIC (vips_gmic_get_type())
#define VIPS_GMIC( obj )                                    \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj),                       \
                               VIPS_TYPE_GMIC, VipsGMic ))
#define VIPS_LAYER_CLASS( klass )                           \
	(G_TYPE_CHECK_CLASS_CAST( (klass),                        \
                            VIPS_TYPE_GMIC, VipsGMicClass))
#define VIPS_IS_LAYER( obj )                            \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_GMIC ))
#define VIPS_IS_LAYER_CLASS( klass )                    \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_GMIC ))
#define VIPS_LAYER_GET_CLASS( obj )                             \
	(G_TYPE_INSTANCE_GET_CLASS( (obj),                            \
                              VIPS_TYPE_GMIC, VipsGMicClass ))


extern "C" {
  G_DEFINE_TYPE( VipsGMic, vips_gmic, VIPS_TYPE_OPERATION );
}


static int gmic_get_tile_border( VipsGMic* vipsgmic )
{
  return vipsgmic->padding;
}

// copy part of a vips region into a cimg
template<typename T> static void
vips_to_gmic( VipsRegion *in, VipsRect *area, CImg<T>* img )
{
  VipsImage *im = in->im;

  for( int y = 0; y < area->height; y++ ) {
    T *p = (T *) VIPS_REGION_ADDR( in, area->left, area->top + y );

    for( int x = 0; x < area->width; x++ ) {
      for( int z = 0; z < im->Bands; z++ ) {
        //const unsigned long off = (unsigned long)img->offset(x,y,z,c);
        (*img)( (unsigned int)x, (unsigned int)y, (unsigned int)z, 0 ) = p[z];
      }
      p += im->Bands;
    }
  }
}

// write a CImg to a vips region
// fill out->valid, img has pixels in img_rect
template<typename T> static void 
gmic_to_vips( gmic_image<T> *img, VipsRect *img_rect, VipsRegion *out )
{
  VipsImage *im = out->im;
  VipsRect *valid = &out->valid;

  g_assert( vips_rect_includesrect( img_rect, valid ) );
	
  int x_off = valid->left - img_rect->left;
  int y_off = valid->top - img_rect->top;

  for( int y = 0; y < valid->height; y++ ) {
    T *p = (T *) VIPS_REGION_ADDR( out, valid->left, valid->top + y );

    for( int x = 0; x < valid->width; x++ ) {
      for( int z = 0; z < im->Bands; z++ )
        p[z] = static_cast<T>( (*img)( 
                                      (unsigned int)(x + x_off), (unsigned int)(y + y_off), (unsigned int)z, 0 ) );

      p += im->Bands;
    }
  }
}

template<typename T> static int
_gmic_gen( VipsRegion *oreg, void *seq, void *a, void *b, gboolean *stop )
{
  VipsRegion **ir = (VipsRegion **) seq;
  VipsGMic *vipsgmic = (VipsGMic *) b;
  
  const int tile_border = gmic_get_tile_border( vipsgmic );

  const VipsRect *r = &oreg->valid;
  VipsRect* need = vips_rect_dup( r );
  std::cout<<"_gmic_gen(): need before adjust="<<need->left<<","<<need->top<<"+"<<need->width<<"+"<<need->height<<std::endl;
  std::cout<<"_gmic_gen(): tile_border="<<tile_border<<std::endl;
  vips_rect_marginadjust( need, tile_border );
  std::cout<<"_gmic_gen(): need after adjust="<<need->left<<","<<need->top<<"+"<<need->width<<"+"<<need->height<<std::endl;
  VipsRect image;

  if( !ir ) return -1;

  image.left = 0;
  image.top = 0;
  image.width = ir[0]->im->Xsize;
  image.height = ir[0]->im->Ysize;
  vips_rect_intersectrect( need, &image, need );
  std::cout<<"_gmic_gen(): need="<<need->left<<","<<need->top<<"+"<<need->width<<"+"<<need->height<<std::endl;
  for( int i = 0; ir[i]; i++ ) {
    if( vips_region_prepare( ir[i], need ) ) {
      vips_free( need );
      return( -1 );
    }
  }

  //CImg<T> img;
  //vips_to_gmic<T>( ir[0], need, &img );
  /**/
  gmic gmic_instance;   // Construct first an empty 'gmic' instance.
  gmic_list<T> images;          // List of images, will contain all images pixel data.
  gmic_list<char> images_names; // List of images names. Can be left empty if no names are associated to images.
  try {
    images.assign( (unsigned int)vipsgmic->ninput );
    for( int i = 0; ir[i]; i++ ) {
      gmic_image<T>& img = images._data[i];
      img.assign(need->width,need->height,1,ir[i]->im->Bands);
      vips_to_gmic<T>( ir[0], need, &img );
    }

    printf("G'MIC command: %s\n",vipsgmic->command);
    std::cout<<"  ninput="<<vipsgmic->ninput
             <<std::endl;
    std::cout<<"  padding="<<vipsgmic->padding
             <<"  x scale="<<vipsgmic->x_scale<<std::endl;

    gmic_instance.run(vipsgmic->command,images,images_names);
		gmic_to_vips<T>( &images._data[0], need, oreg );
  }
  catch( gmic_exception e ) { 
    images.assign((unsigned int)0);

		vips_error( "VipsGMic", "%s", e.what() );

		return( -1 );
  }
  images.assign((unsigned int)0);
  /**/

	return( 0 );
}


static int
gmic_gen( VipsRegion *oreg, void *seq, void *a, void *b, gboolean *stop )
{
  VipsRegion **ir = (VipsRegion **) seq;
  
  if( !ir ) return -1;

  std::cout<<"ir[0]->im->BandFmt: "<<ir[0]->im->BandFmt<<std::endl;
  switch( ir[0]->im->BandFmt ) {
  case VIPS_FORMAT_UCHAR:
    //return _gmic_gen<unsigned char>(oreg, seq, a, b, stop);
    break;

  case VIPS_FORMAT_CHAR:
    break;

  case VIPS_FORMAT_USHORT:
    //return _gmic_gen<unsigned short int>(oreg, seq, a, b, stop);
    break;

  case VIPS_FORMAT_SHORT:
    break;

  case VIPS_FORMAT_UINT:
    break;

  case VIPS_FORMAT_INT:
    break;

  case VIPS_FORMAT_FLOAT:
    return _gmic_gen<float>(oreg, seq, a, b, stop);
    break;

  case VIPS_FORMAT_DOUBLE:
    break;

  default:
    g_assert( 0 );
    break;
  }

  return 0;
}


static int _gmic_build( VipsObject *object )
{
  VipsObjectClass *klass = VIPS_OBJECT_GET_CLASS( object );
  //VipsOperation *operation = VIPS_OPERATION( object );
  VipsGMic *vipsgmic = (VipsGMic *) object;
  int i;

  if( vipsgmic->ninput < 1 ) return -1;
  if( !(vipsgmic->in[0]) ) return -1;

  if( VIPS_OBJECT_CLASS( vips_gmic_parent_class )->build( object ) )
    return( -1 );

  for( i = 0; i < vipsgmic->ninput; i++ ) {
    if( vips_image_pio_input( vipsgmic->in[i] ) || 
        vips_check_coding_known( klass->nickname, vipsgmic->in[i] ) )  
      return( -1 );
  }
  
  /* Get ready to write to @out. @out must be set via g_object_set() so
   * that vips can see the assignment. It'll complain that @out hasn't
   * been set otherwise.
   */
  g_object_set( vipsgmic, "out", vips_image_new(), NULL ); 

  VipsImage** in = (VipsImage**)im_malloc( vipsgmic->out, sizeof(VipsImage*)*(vipsgmic->ninput+1) );
  if( !in ) return( -1 );

  for( i = 0; i < vipsgmic->ninput; i++ ) {
    in[i] = vipsgmic->in[i];
  }
  in[vipsgmic->ninput] = NULL;

  /* Set demand hints. 
   */
  if( vips_image_pipeline_array( vipsgmic->out, 
                                 VIPS_DEMAND_STYLE_ANY,
                                 in ) )
    return( -1 );

  vips_image_init_fields( vipsgmic->out,
                          in[0]->Xsize, in[0]->Ysize, 
                          in[0]->Bands, in[0]->BandFmt,
                          in[0]->Coding, in[0]->Type,
                          1.0, 1.0);

  if(vipsgmic->ninput > 0) {
    if( vips_image_generate( vipsgmic->out,
                             vips_start_many, gmic_gen, vips_stop_many, 
                             in, vipsgmic ) )
      return( -1 );
  } else {
    if( vips_image_generate( vipsgmic->out, 
                             NULL, gmic_gen, NULL, NULL, vipsgmic ) )
      return( -1 );
  }

  return( 0 );
}


static void
vips_gmic_class_init( VipsGMicClass *klass )
{
  GObjectClass *gobject_class = G_OBJECT_CLASS( klass );
  VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( klass );
  VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( klass );
  gobject_class->set_property = vips_object_set_property;
  gobject_class->get_property = vips_object_get_property;
  vobject_class->nickname = "gmic";
  vobject_class->description = _( "Vips G'MIC" );
  vobject_class->build = _gmic_build;
  operation_class->flags = VIPS_OPERATION_SEQUENTIAL_UNBUFFERED;

  VIPS_ARG_INT( klass, "ninput", 0, 
                _( "NInput" ), 
                _( "Number of input images" ),
                VIPS_ARGUMENT_REQUIRED_INPUT, 
                G_STRUCT_OFFSET( VipsGMic, ninput ),
                0, GMIC_MAX_INPUT_IMAGES, 0 );

  VIPS_ARG_IMAGE( klass, "out", 1,
                  _( "Output" ), 
                  _( "Output image" ),
                  VIPS_ARGUMENT_REQUIRED_OUTPUT, 
                  G_STRUCT_OFFSET( VipsGMic, out ) );

  VIPS_ARG_INT( klass, "padding", 3,
                _( "padding" ), 
                _( "Tile overlap" ),
                VIPS_ARGUMENT_REQUIRED_INPUT, 
                G_STRUCT_OFFSET( VipsGMic, padding ),
                0, INT_MAX, 0);

  VIPS_ARG_DOUBLE( klass, "x_scale", 4,
                   _( "x_scale" ), 
                   _( "X Scale" ),
                   VIPS_ARGUMENT_REQUIRED_INPUT, 
                   G_STRUCT_OFFSET( VipsGMic, x_scale ),
                   0, 100000000, 1);

  VIPS_ARG_DOUBLE( klass, "y_scale", 5,
                   _( "y_scale" ), 
                   _( "Y Scale" ),
                   VIPS_ARGUMENT_REQUIRED_INPUT, 
                   G_STRUCT_OFFSET( VipsGMic, y_scale ),
                   0, 100000000, 1);

	VIPS_ARG_STRING( klass, "command", 10, 
                   _( "command" ),
                   _( "G'MIC command string" ),
                   VIPS_ARGUMENT_REQUIRED_INPUT, 
                   G_STRUCT_OFFSET( VipsGMic, command ),
                   NULL );

  char tstr[100];
  char tstr2[100];
  char tstr3[100];
  for( int imgid = 0; imgid < GMIC_MAX_INPUT_IMAGES; imgid++ ) {
    snprintf(tstr,99,"in%d",imgid);
    snprintf(tstr2,99,"Input%d",imgid);
    snprintf(tstr3,99,"Input image %d",imgid);
    VIPS_ARG_IMAGE( klass, tstr, imgid+11, 
                    _( tstr2 ), 
                    _( tstr3 ),
                    VIPS_ARGUMENT_OPTIONAL_INPUT,
                    G_STRUCT_OFFSET( VipsGMic, in )+sizeof(VipsImage*)*imgid );
  }
}


static void
vips_gmic_init( VipsGMic *vipsgmic )
{
}


int
vips_gmic(int n, VipsImage** out, const char* command, int padding, float x_scale, float y_scale,...)
{
  va_list ap;
  int result;
  va_start( ap, y_scale );
  //result = vips_call_split( "vips_gmic", ap, n, out, command, padding, x_scale, y_scale );
  result = vips_call_split( "gmic", ap, n, out, padding, x_scale, y_scale, command );
  va_end( ap );
  return( result );
}
