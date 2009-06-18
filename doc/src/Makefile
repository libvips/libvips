#

PDF = vipsmanual.pdf 
SRC = \
	applintro.tex \
	cppintro.tex \
	fileformat.tex \
	func.tex \
	format.tex \
	iosys.tex \
	ipio.tex \
	mydefs.tex \
	operintro.tex \
	packages.tex \
	pio.tex \
	refintro.tex \
	vdisplay.tex \
	verror.tex \
	vimage.tex \
	vipsmanual.tex \
	vmask.tex \
	wio.tex

mkinstalldirs = $(SHELL) ../../mkinstalldirs
destdir = ../

all: $(PDF) html

install: all $(PDF) html
	-rm -rf ${destdir}/pdf/*.pdf
	-rm -rf ${destdir}/html/manual/vips*
	-rm -rf ${destdir}/html/manual/figs
	$(mkinstalldirs) ${destdir}/pdf
	$(mkinstalldirs) ${destdir}/html/manual
	-cp $(PDF) ${destdir}/pdf
	-cp -r vipsmanual/* ${destdir}/html/manual

$(PDF): $(SRC) 
	pdflatex vipsmanual.tex
	pdflatex vipsmanual.tex

.PHONEY: html
html: 
	-rm -rf vipsmanual 
	mkdir vipsmanual
	htlatex vipsmanual.tex html.cfg,3 "" -dvipsmanual/
	cp -r figs vipsmanual
	-rm vipsmanual/figs/*.svg
	-rm vipsmanual/*.png

.PHONEY: clean 
clean:
	-rm -f *.4ct
	-rm -f *.4tc
	-rm -f *.log
	-rm -f *.xref
	-rm -f *.tmp
	-rm -f *.html
	-rm -f *.css
	-rm -f *.lg
	-rm -f *.idv
	-rm -f *.aux
	-rm -f *.dvi
	-rm -f *.lof
	-rm -f *.lot
	-rm -f *.toc
	-rm -f *.pdf
	-rm -rf vipsmanual
