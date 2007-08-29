/* Header for vips2dj.
 */

/*

    Copyright (C) 1991-2003 The National Gallery

    This program is free software; you can redistribute it and/or modify
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

/* Geometry for a printer model.
 */
typedef struct {
	char *name;		/* Printer name (eg. "2500cp") */
	int pwidth;		/* Paper width (36/54 inches) */
	int width;		/* Printable width, points */
	int length;		/* Printable length, points */
	int left;		/* Left margin, points */
	int top;		/* Top margin, points */
} PrinterGeometry;

/* All the models.
 */
extern PrinterGeometry printer_data[];

extern int vips2asciihex( IMAGE *in, FILE *out );
