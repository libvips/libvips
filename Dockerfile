FROM alpine

ARG VIPS_VERSION

RUN apk update

RUN apk add build-base pkgconfig glib-dev gobject-introspection-dev expat-dev tiff-dev libjpeg-turbo-dev libexif-dev giflib-dev librsvg-dev lcms2-dev libpng-dev orc-dev libwebp-dev libheif-dev

RUN apk add libimagequant-dev --repository=http://dl-cdn.alpinelinux.org/alpine/edge/testing

RUN https://github.com/libvips/libvips/releases/download/v${VIPS_VERSION}/vips-${VIPS_VERSION}.tar.gz

RUN mkdir vips

RUN tar xvzf vips-${VIPS_VERSION}.tar.gz -C vips --strip-components 1

WORKDIR /vips

RUN ./configure --enable-debug=no --without-python

RUN make

RUN make install

RUN ldconfig

WORKDIR /

RUN rm -rf vips
