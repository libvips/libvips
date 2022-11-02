# Shell completions for vips

Basic shell completions for the `vips` program. Internally, these use the
`-c` argument to `vips` to list argument options.

## Example

```
$ vips relational<TAB>
relational        relational_const  
$ vips relational_const ~/pics/k2.<TAB>
~/pics/k2.avif  ~/pics/k2.hdr   ~/pics/k2.pdf   ~/pics/k2.tif
~/pics/k2.bmp   ~/pics/k2.heic  ~/pics/k2.pfm   ~/pics/k2.v
~/pics/k2.csv   ~/pics/k2.jp2   ~/pics/k2.pgm   ~/pics/k2.vips
~/pics/k2.fits  ~/pics/k2.jpg   ~/pics/k2.png   ~/pics/k2.webp
~/pics/k2.flif  ~/pics/k2.jxl   ~/pics/k2.ppm   
~/pics/k2.gif   ~/pics/k2.pbm   ~/pics/k2.ppt   
$ vips relational_const ~/pics/k2.jpg x.v less<TAB>
less    lesseq  
$ vips relational_const ~/pics/k2.jpg x.v lesseq 12
```

## Install

### `vips-completion.bash` 

Usually copy to `/etc/bash_completion.d` to install, but it depends on your
system.
