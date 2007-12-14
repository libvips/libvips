/* SWIG interface file for vipsCC7
 *
 * 5/9/07
 *      - use g_option_context_set_ignore_unknown_options() so we don't fail
 *        on unrecognied -args (thanks Simon)
 */

%module VImage
%{
#include <vips/vipscpp.h>
%}
/* Need to override assignment to get refcounting working.
 */
%rename(__assign__) vips::VImage::operator=;

/* We wrap the C++ VImage class as VImage_core, then write the user-visible
 * VImage class ourselves with a %pythoncode (see below). Our hand-made VImage
 * class wraps all the operators from the VIPS image operation database via
 * __getattr__.
 */
%rename(VImage_core) VImage;

%include "std_list.i"
%include "std_complex.i"
%include "std_vector.i"
%include "std_except.i"

%import "VError.i"
%import "VMask.i"
%import "VDisplay.i"

namespace std {
  %template(IntVector) vector<int>;
  %template(DoubleVector) vector<double>;
  %template(ImageVector) vector<VImage>;
}

/* VImage defines a lot of other operator overloads ... but SWIGs autowrapping
 * doesn't work well for them. Do by hand later.
 */
%include vips/VImage.h

/* Now wrap SWIG's VImage_core with our own VImage class which does operations
 * from the VIPS operation database.
 */
%pythoncode %{
class VImage (VImage_core):
        def __getattr__ (self, name):
                print "VImage getattr: ", name
%}

/* Helper code for vips_init().
 */
%{
#include <vips/vips.h>

/* Turn on to print args.
#define DEBUG
 */

/* Command-line args during parse.
 */
typedef struct _Args {
	/* The n strings we alloc when we get from Python.
	 */
	int n;
	char **str;

	/* argc/argv as processed by us.
	 */
	int argc;
	char **argv;
} Args;

#ifdef DEBUG
static void
args_print (Args *args)
{
        int i;

	printf ("args_print: argc = %d\n", args->argc);
	// +1 so we print the trailing NULL too
	for (i = 0; i < args->argc + 1; i++)
		printf( "\t%2d)\t%s\n", i, args->argv[i]);
}
#endif /*DEBUG*/

static void
args_free (Args *args)
{
	int i;

	for (i = 0; i < args->n; i++)
		IM_FREE (args->str[i]);
	args->n = 0;
	args->argc = 0;
	IM_FREE (args->str);
	IM_FREE (args->argv);
	IM_FREE (args);
}

/* Get argv/argc from python.
 */
static Args *
args_new (void)
{
	Args *args;
	PyObject *av;
	int i;
	int n;

	args = g_new (Args, 1);
	args->n = 0;
	args->str = NULL;
	args->argc = 0;
	args->argv = NULL;

	if (!(av = PySys_GetObject ((char *) "argv"))) 
		return (args);
	if (!PyList_Check (av)) {
		PyErr_Warn (PyExc_Warning, "ignoring sys.argv: "
			"it must be a list of strings");
                return (args);
        }

        n = PyList_Size (av);
	args->str = g_new (char *, n);
	for (i = 0; i < n; i++)
		args->str[i] = g_strdup 
			(PyString_AsString (PyList_GetItem (av, i)));
	args->n = n;

	/* +1 for NULL termination.
	 */
	args->argc = n;
	args->argv = g_new (char *, n + 1);
	for (i = 0; i < n; i++)
		args->argv[i] = args->str[i];
	args->argv[i] = NULL;

	return (args);
}

static void
vips_fatal (const char *msg)
{
	char buf[256];

	im_snprintf (buf, 256, "%s\n%s", msg, im_error_buffer());
	im_error_clear();
	Py_FatalError (buf);
}

%}

%init %{
{
        Args *args;
        
        args = args_new ();

#ifdef DEBUG
	printf ("on startup:\n");
	args_print (args);
#endif /*DEBUG*/
        
        if (im_init_world (args->argv[0])) {
            args_free (args);
            vips_fatal ("can't initialise module vips");
        }

        /* Now parse any GOptions. 
       	 */
	GError *error = NULL;
	GOptionContext *context;

	context = g_option_context_new ("- vips");
	g_option_context_add_group (context, im_get_option_group());

        g_option_context_set_ignore_unknown_options (context, TRUE);
	if( !g_option_context_parse (context, 
		&args->argc, &args->argv, &error)) {
		g_option_context_free (context);
		args_free (args);
		im_error( "vipsmodule", "%s", error->message);
		g_error_free (error);
		vips_fatal ("can't initialise module vips_core");
	}
	g_option_context_free (context);

#ifdef DEBUG
	printf ("after parse:\n");
	args_print (args);
#endif /*DEBUG*/

	// Write (possibly) modified argc/argv back again.
	if (args->argv) 
		PySys_SetArgv (args->argc, args->argv);

        args_free (args);
}
%}

