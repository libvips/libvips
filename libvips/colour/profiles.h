/* The fallback profiles, coded as a set of base64 strings, see 
 * wrap-profiles.sh
 */
typedef struct _VipsCodedProfile {
	const char *name;
	int length;
	const unsigned char data[];
} VipsCodedProfile;

extern VipsCodedProfile *vips__coded_profiles[];

