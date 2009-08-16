/* SWIG interface file for vipsCC7
 *
 * 5/9/07
 *      - use g_option_context_set_ignore_unknown_options() so we don't fail
 *        on unrecognied -args (thanks Simon)
 * 3/8/08
 *      - add .tobuffer() / .frombuffer (), .tostring (), .fromstring ()
 *        methods
 *      - add PIL_mode_from_vips () and vips_from_PIL_mode () utility
 *        functions
 */

%module VImage

%{
#include <vipsCC/vipscpp.h>

/* We need the C API too for the args init and some of the
 * frombuffer/tobuffer stuff.
 */
#include <vips/vips.h>
%}

/* Need to override assignment to get refcounting working.
 */
%rename(__assign__) vips::VImage::operator=;

%include "std_list.i"
%include "std_complex.i"
%include "std_vector.i"
%include "std_except.i"
%include "std_string.i"
%include "cstring.i"

%import "VError.i"
%import "VMask.i"
%import "VDisplay.i"

namespace std {
  %template(IntVector) vector<int>;
  %template(DoubleVector) vector<double>;
  %template(ImageVector) vector<VImage>;
}

/* To get image data to and from VImage (eg. when interfacing with PIL) we
 * need to be able to import and export Python buffer() objects. Add new
 * methods to construct from and return pointer/length pairs, then wrap them
 * ourselves with a couple of typemaps.
 */

%{
struct VBuffer {
  void *data;
  size_t size;
};
%}

%typemap (out) VBuffer {
  $result = PyBuffer_FromMemory ($1.data, $1.size);
}

%typemap (in) VBuffer {
  const char *buffer;
  Py_ssize_t buffer_len;

  if (PyObject_AsCharBuffer ($input, &buffer, &buffer_len) == -1) {
    PyErr_SetString (PyExc_TypeError,"Type error. Unable to get char pointer from buffer");
    return NULL;
  }

  $1.data = (void *) buffer;
  $1.size = buffer_len;
}

/* Need the expanded VImage.h in this directory, rather than the usual
 * vips/VImage.h. SWIG b0rks on #include inside class definitions.
 */
%include VImage.h

%extend vips::VImage {
public:
  VBuffer tobuffer () throw (VError)
  {
    VBuffer buffer;

    buffer.data = $self->data ();
    buffer.size = (size_t) $self->Xsize () * $self->Ysize () * 
        IM_IMAGE_SIZEOF_PEL ($self->image ());

    return buffer;
  }

  static VImage frombuffer (VBuffer buffer, int width, int height,
    int bands, TBandFmt format) throw (VError)
  {
    return VImage (buffer.data, width, height, bands, format);
  }

  %cstring_output_allocate_size (char **buffer, int *buffer_len, im_free (*$1))

  void tostring (char **buffer, int *buffer_len) throw (VError)
  {
    void *vips_memory;

    /* Eval the vips image first. This may throw an exception and we want to
     * make sure we do this before we try to malloc() space for the copy.
     */
    vips_memory = $self->data ();

    /* We have to copy the image data to make a string that Python can
     * manage. Use frombuffer() / tobuffer () if you want to avoid the copy
     * and manage memory lifetime yourself.
     */
    *buffer_len = (size_t) $self->Xsize () * $self->Ysize () * 
      IM_IMAGE_SIZEOF_PEL ($self->image ());
    if (!(*buffer = (char *) im_malloc (NULL, *buffer_len))) 
      verror ("Unable to allocate memory for image copy.");
    memcpy (*buffer, vips_memory, *buffer_len);
  }

  static VImage fromstring (std::string buffer, int width, int height,
    int bands, TBandFmt format) throw (VError)
  {
    void *vips_memory;
    VImage result;

    /* We have to copy the string, then add a callback to the VImage to free
     * it when we free the VImage. Use frombuffer() / tobuffer () if you want 
     * to avoid the copy and manage memory lifetime yourself.
     */
    if (!(vips_memory = im_malloc (NULL, buffer.length ()))) 
      verror ("Unable to allocate memory for image copy.");

    /* We have to use .c_str () since the string may not be contiguous.
     */
    memcpy (vips_memory, buffer.c_str (), buffer.length ());
    result = VImage (vips_memory, width, height, bands, format);

    if (im_add_close_callback (result.image (), 
      (im_callback_fn) im_free, vips_memory, NULL))
      verror ();

    return result;
  }
}

%pythoncode %{
# try to guess a PIL mode string from a VIPS image
def PIL_mode_from_vips (vim):
  if vim.Bands () == 3 and vim.BandFmt () == VImage.FMTUCHAR:
    return 'RGB'
  elif vim.Bands () == 4 and vim.BandFmt () == VImage.FMTUCHAR and vim.Type == VImage.VImage.RGB:
    return 'RGBA'
  elif vim.Bands () == 4 and vim.BandFmt () == VImage.FMTUCHAR and vim.Type == VImage.CMYK:
    return 'CMYK'
  elif vim.Bands () == 1 and vim.BandFmt () == VImage.FMTUCHAR:
    return 'L'
  elif vim.Bands () == 1 and vim.BandFmt () == VImage.FMTINT:
    return 'I'
  elif vim.Bands () == 1 and vim.BandFmt () == VImage.FMTFLOAT:
    return 'F'
  elif vim.Bands () == 2 and vim.BandFmt () == VImage.FMTUCHAR:
    return 'LA'
  else:
    raise ValueError ('unsupported vips -> pil image')

# return vips (bands, format, type) for a PIL mode
def vips_from_PIL_mode (mode):
  if mode == 'RGB':
    return (3, VImage.FMTUCHAR, VImage.RGB)
  elif mode == 'RGBA':
    return (4, VImage.FMTUCHAR, VImage.RGB)
  elif mode == 'CMYK':
    return (4, VImage.FMTUCHAR, VImage.CMYK)
  elif mode == 'L':
    return (1, VImage.FMTUCHAR, VImage.B_W)
  elif mode == 'I':
    return (1, VImage.FMTINT, VImage.B_W)
  elif mode == 'F':
    return (1, VImage.FMTFLOAT, VImage.B_W)
  elif mode == 'LA':
    return (2, VImage.FMTUCHAR, VImage.B_W)
  else:
    raise ValueError ('unsupported pil -> vips image')
%}

/* Helper code for vips_init().
 */
%{
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
    printf ("\t%2d)\t%s\n", i, args->argv[i]);
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
    return args;
  }

  n = PyList_Size (av);
  args->str = g_new (char *, n);
  for (i = 0; i < n; i++)
    args->str[i] = g_strdup (PyString_AsString (PyList_GetItem (av, i)));
  args->n = n;

  /* +1 for NULL termination.
   */
  args->argc = n;
  args->argv = g_new (char *, n + 1);
  for (i = 0; i < n; i++)
    args->argv[i] = args->str[i];
  args->argv[i] = NULL;

  return args;
}

static void
vips_fatal (const char *msg)
{
  char buf[256];

  im_snprintf (buf, 256, "%s\n%s", msg, im_error_buffer());
  im_error_clear ();
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
  if (!g_option_context_parse (context, 
    &args->argc, &args->argv, &error)) {
    g_option_context_free (context);
    args_free (args);
    im_error ("vipsmodule", "%s", error->message);
    g_error_free (error);
    vips_fatal ("can't initialise module vips");
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

