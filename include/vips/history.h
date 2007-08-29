/* @(#) Useful macros for appending one line in the History field of the
 * @(#) output image descriptor when a function is called
 * @(#)  The main program should use im_updatehist()
 * @(#) The added line corresponds to the command relevant to the function
 * @(#) for instance
 * @(#) for the function: im_add(in1, in2, out) the following lines of code can
 * @(#) be used to add a line of history in the Hist member 
 * @(#) of the out image descriptor
 * @(#) ....
 * @(#) IMAGE *in1, *in2, *out;
 * @(#) ....
 * @(#) if ( im_add(in1, in2, out) == -1 ) return(-1);
 * @(#) if ( IM_ADD(in1, in2, out) == -1 ) return(-1);
 * @(#) ....
 * @(#)
 * @(#)  The first function will add the two images in1 and in2,
 * @(#) whereas the second call will append
 * @(#) at the history descriptor of out the line:
 * @(#) add infile outfile # date
 * @(#) where infile is in.filename and outfile is out.filename
 * @(#)  The history line has been prepared in such a way that the first
 * @(#) argument is the UNIX command which corresponds to the function
 * @(#)  As a general rule, all functions in im_funcs directory which 
 * @(#) have a correponding command in src directory are listed here
 * @(#)
 * @(#)  Since the macros presented in this file correspond to the function
 * @(#) im_histlin() the returned value is 0 on success and -1 on error.
 * @(#)
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

/* Made obsolete by the function database stuff ... just here in case anyone
 * still includes it.
 */
