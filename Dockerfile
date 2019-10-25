FROM alpine:3.10

ARG VIPS_VERSION

RUN apk add --update --no-cache --repository=http://dl-cdn.alpinelinux.org/alpine/edge/testing --virtual .build-deps \
            build-base \
            pkgconfig \
            glib-dev \
            gobject-introspection-dev \
            expat-dev \
            tiff-dev \
            libjpeg-turbo-dev \
            libexif-dev giflib-dev \
            librsvg-dev \
            lcms2-dev \
            libpng-dev \
            orc-dev \
            libwebp-dev \
            libheif-dev \
            libimagequant-dev 

RUN wget https://github.com/libvips/libvips/releases/download/v${VIPS_VERSION}/vips-${VIPS_VERSION}.tar.gz

RUN mkdir vips

RUN tar xvzf vips-${VIPS_VERSION}.tar.gz -C vips --strip-components 1

WORKDIR /vips

RUN ./configure --enable-debug=no --without-python

RUN make

RUN make install

RUN ldconfig

WORKDIR /

RUN rm -rf vips

RUN apk del .build-deps

RUN apk add --update --no-cache libgsf glib gobject-introspection expat tiff libjpeg-turbo libexif giflib librsvg lcms2 libpng orc libwebp libheif

RUN apk add --update --no-cache libimagequant --repository=http://dl-cdn.alpinelinux.org/alpine/edge/testing

ENV GI_TYPELIB_PATH /usr/local/lib/girepository-1.0

CMD /usr/local/bin/vips
