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

```
$ vips -l matload
    VipsForeignLoadMat (matload), load mat from file (.mat),
        priority=0, untrusted, is_a, get_flags, get_flags_filename,
        header, load
```

Please do not submit reports for untrusted loaders.

## Reporting a Vulnerability

If you think you've identified a security issue in a project under the
libvips umbrella, please **do not** report the issue publicly via a mailing
list, gitter, a public issue on the github issue tracker, a merge request,
or any other public venue.

Instead, report a [*confidential* issue in the github issue
tracker](https://github.com/libvips/libvips/-/issues/new?issue[confidential]=1),
with the “This issue is confidential” box checked. Please include as many
details as possible, including a minimal reproducible example of the issue,
and an idea of how exploitable/severe you think it is.

(FIXME ... we need to set this up and test it)

If you have patches which fix the security issue, please attach them to
your confidential issue as patch files.

Confidential issues are only visible to the reporter and the libvips
maintainers.

As the next steps are then:

 * The report is triaged.
 * Code is audited to find any potential similar problems.
 * If it is determined, in consultation with the submitter, that a CVE is
   required, we will obtain one.
 * The fix is prepared for the development branch, and for the most recent
   stable branch.
 * The fix is submitted to the public repository.
 * On the day the issue and fix are made public, an announcement is made on the
   [public channels listed below](#Security-Announcements).
 * A new release containing the fix is issued.

## Security Announcements

(FIXME ... add an announcement mechanism)

## Acknowledgements

This text was partially based with thanks on the [glib security
policy](https://raw.githubusercontent.com/GNOME/glib/refs/heads/main/SECURITY.md).


