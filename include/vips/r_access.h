/* r_access.h
 *
 * 2006-09-21 tcv
 * random access to images and regions
 */

#ifndef IM_R_ACCESS_H
#define IM_R_ACCESS_H

#include <vips/vips.h>


/** ARRAY MEMBER MACROS **/
/* these are local */

#define IM__TYPE_FROM_ARRAY(type,vptr,i)    ( ((type*) (vptr))[i] )

#define   IM__CHAR_FROM_ARRAY(vptr,i)  IM__TYPE_FROM_ARRAY( gint8,   (vptr), (i) )
#define  IM__UCHAR_FROM_ARRAY(vptr,i)  IM__TYPE_FROM_ARRAY( guint8,  (vptr), (i) )
#define  IM__SHORT_FROM_ARRAY(vptr,i)  IM__TYPE_FROM_ARRAY( gint16,  (vptr), (i) )
#define IM__USHORT_FROM_ARRAY(vptr,i)  IM__TYPE_FROM_ARRAY( guint16, (vptr), (i) )
#define    IM__INT_FROM_ARRAY(vptr,i)  IM__TYPE_FROM_ARRAY( gint32,  (vptr), (i) )
#define   IM__UINT_FROM_ARRAY(vptr,i)  IM__TYPE_FROM_ARRAY( guint32, (vptr), (i) )
#define  IM__FLOAT_FROM_ARRAY(vptr,i)  IM__TYPE_FROM_ARRAY( float,   (vptr), (i) )
#define IM__DOUBLE_FROM_ARRAY(vptr,i)  IM__TYPE_FROM_ARRAY( double,  (vptr), (i) )

#define IM__VALUE_FROM_ARRAY(band_fmt,vptr,i)  (                                 \
     ( IM_BANDFMT_DOUBLE == (band_fmt) ) ? IM__DOUBLE_FROM_ARRAY( (vptr), (i) )  \
   :  ( IM_BANDFMT_FLOAT == (band_fmt) ) ?  IM__FLOAT_FROM_ARRAY( (vptr), (i) )  \
   :    ( IM_BANDFMT_INT == (band_fmt) ) ?    IM__INT_FROM_ARRAY( (vptr), (i) )  \
   :   ( IM_BANDFMT_UINT == (band_fmt) ) ?   IM__UINT_FROM_ARRAY( (vptr), (i) )  \
   :  ( IM_BANDFMT_SHORT == (band_fmt) ) ?  IM__SHORT_FROM_ARRAY( (vptr), (i) )  \
   : ( IM_BANDFMT_USHORT == (band_fmt) ) ? IM__USHORT_FROM_ARRAY( (vptr), (i) )  \
   :   ( IM_BANDFMT_CHAR == (band_fmt) ) ?   IM__CHAR_FROM_ARRAY( (vptr), (i) )  \
   :                                        IM__UCHAR_FROM_ARRAY( (vptr), (i) ) )

#define IM__ARRAY_ASSIGNMENT(band_fmt,vptr,i,val)  (                                        \
     ( IM_BANDFMT_DOUBLE == (band_fmt) ) ? ( IM__DOUBLE_FROM_ARRAY( (vptr), (i) )= (val) )  \
   :  ( IM_BANDFMT_FLOAT == (band_fmt) ) ? (  IM__FLOAT_FROM_ARRAY( (vptr), (i) )= (val) )  \
   :    ( IM_BANDFMT_INT == (band_fmt) ) ? (    IM__INT_FROM_ARRAY( (vptr), (i) )= (val) )  \
   :   ( IM_BANDFMT_UINT == (band_fmt) ) ? (   IM__UINT_FROM_ARRAY( (vptr), (i) )= (val) )  \
   :  ( IM_BANDFMT_SHORT == (band_fmt) ) ? (  IM__SHORT_FROM_ARRAY( (vptr), (i) )= (val) )  \
   : ( IM_BANDFMT_USHORT == (band_fmt) ) ? ( IM__USHORT_FROM_ARRAY( (vptr), (i) )= (val) )  \
   :   ( IM_BANDFMT_CHAR == (band_fmt) ) ? (   IM__CHAR_FROM_ARRAY( (vptr), (i) )= (val) )  \
   :                                       (  IM__UCHAR_FROM_ARRAY( (vptr), (i) )= (val) ) )

#define IM__ARRAY_INCREMENT(band_fmt,vptr,i,val)  (                                          \
     ( IM_BANDFMT_DOUBLE == (band_fmt) ) ? ( IM__DOUBLE_FROM_ARRAY( (vptr), (i) )+= (val) )  \
   :  ( IM_BANDFMT_FLOAT == (band_fmt) ) ? (  IM__FLOAT_FROM_ARRAY( (vptr), (i) )+= (val) )  \
   :    ( IM_BANDFMT_INT == (band_fmt) ) ? (    IM__INT_FROM_ARRAY( (vptr), (i) )+= (val) )  \
   :   ( IM_BANDFMT_UINT == (band_fmt) ) ? (   IM__UINT_FROM_ARRAY( (vptr), (i) )+= (val) )  \
   :  ( IM_BANDFMT_SHORT == (band_fmt) ) ? (  IM__SHORT_FROM_ARRAY( (vptr), (i) )+= (val) )  \
   : ( IM_BANDFMT_USHORT == (band_fmt) ) ? ( IM__USHORT_FROM_ARRAY( (vptr), (i) )+= (val) )  \
   :   ( IM_BANDFMT_CHAR == (band_fmt) ) ? (   IM__CHAR_FROM_ARRAY( (vptr), (i) )+= (val) )  \
   :                                       (  IM__UCHAR_FROM_ARRAY( (vptr), (i) )+= (val) ) )


/** IMAGE MEMBER MACROS **/
/* export these */

#define IM_IMAGE_VALUE(im,x,y,band)             IM__VALUE_FROM_ARRAY( (im)-> BandFmt, \
                                                  IM_IMAGE_ADDR( (im), (x), (y) ), (band) )

#define IM_IMAGE_ASSIGNMENT(im,x,y,band,val)    IM__ARRAY_ASSIGNMENT( (im)-> BandFmt, \
                                                  IM_IMAGE_ADDR( (im), (x), (y) ), (band), (val) )

#define IM_IMAGE_INCREMENT(im,x,y,band,val)     IM__ARRAY_INCREMENT( (im)-> BandFmt, \
                                                  IM_IMAGE_ADDR( (im), (x), (y) ), (band), (val) )


/** REGION MEMBER MACROS **/
/* export these */

#define IM_REGION_VALUE(reg,x,y,band)           IM__VALUE_FROM_ARRAY( (reg)-> im-> BandFmt, \
                                                  IM_REGION_ADDR( (reg), (x), (y) ), (band) )

#define IM_REGION_ASSIGNMENT(reg,x,y,band,val)  IM__ARRAY_ASSIGNMENT( (reg)-> im-> BandFmt, \
                                                  IM_REGION_ADDR( (reg), (x), (y) ), (band), (val) )

#define IM_REGION_INCREMENT(reg,x,y,band,val)   IM__ARRAY_INCREMENT( (reg)-> im-> BandFmt, \
                                                  IM_REGION_ADDR( (reg), (x), (y) ), (band), (val) )


#endif /* IM_R_ACCESS_H */

