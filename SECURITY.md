# Security policy for libvips

## Supported Versions

Upstream libvips only supports the most recent stable release series, and
the current development release series. Any older stable release series are
no longer supported, although they may still receive backported security
updates in long-term support distributions. Such support is up to the
distributions, though.

libvips contains deprecated code which is disabled by default.
Please do not report vulnerabilities in this part of the library.

libvips contains loaders for many file formats whose load libraries are
not well tested. These loaders are tagged as `untrusted` in libvips, you
can check the status of a loader with, for example:

```console
$ vips -l matload
    VipsForeignLoadMat (matload), load mat from file (.mat),
        priority=0, untrusted, is_a, get_flags, get_flags_filename,
        header, load
```

Please do not submit reports for untrusted loaders.

## Reporting a Vulnerability

If you think you've identified a security issue in a project under the
libvips umbrella, please **do not** report the issue publicly via a mailing
list, Gitter, a issue on the GitHub issue tracker, a pull request, or any
other public venue.

Instead, [report via email to the
maintainers](https://github.com/google/oss-fuzz/blob/4f9a1fec7341ed2549652724c2c71ff01f01b817/projects/libvips/project.yaml#L4-L7).
Please include as many details as possible, including a minimal reproducible
example of the issue, and an idea of how exploitable/severe you think it is.

The next steps are:

 * The report is triaged.
 * Code is audited to find any potential similar problems.
 * If it is determined, in consultation with the submitter, that a CVE is
   required, we will obtain one. Please do not request your CVE ID, we will
   not recognise it.
 * The fix is prepared for the development branch, and for the most recent
   stable branch.
 * The fix is submitted to the public repository.
 * A new release containing the fix is issued.
 * After a period of grace to allow downstream updates, an announcement will
   be made on the [public channels listed below](#Security-Announcements).

## Security Announcements

Announcements will be made on:

https://github.com/libvips/libvips/security/advisories

## Acknowledgements

This text was based with thanks on the [glib security
policy](https://gitlab.gnome.org/GNOME/glib/-/blob/main/SECURITY.md).


