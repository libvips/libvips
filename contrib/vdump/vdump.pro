%%Pages: 1
%%Creator: vdump
%%EndComments
%%BeginDocument: vdump
/doimage {
   /b exch def /m exch def /n exch def
	/pix n string def
   n m b [n 0 0 m neg 0 m]
   { currentfile pix readhexstring pop }
   image
} def
/spotsize {
   /perinch exch def
   currentscreen 3 -1 roll
   pop perinch
   3 1 roll setscreen
} def
/invert {
   /curtran currenttransfer cvlit def
   /newtran curtran length 3 add array def
   newtran 0 {1 exch sub} putinterval
   newtran 3 curtran putinterval
   newtran cvx settransfer
} def
80 spotsize
