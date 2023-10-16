#!/bin/bash -eu

export PKG_CONFIG="pkg-config --static"
export PKG_CONFIG_PATH="$WORK/lib/pkgconfig"
export CPPFLAGS="-I$WORK/include"
export LDFLAGS="-L$WORK/lib"

# libz
pushd $SRC/zlib
./configure --static --prefix=$WORK
make -j$(nproc) all
make install
popd

# libexif
pushd $SRC/libexif
autoreconf -fi
./configure \
  --enable-static \
  --disable-shared \
  --disable-nls \
  --disable-docs \
  --disable-dependency-tracking \
  --prefix=$WORK
make -j$(nproc)
make install
popd

# lcms
pushd $SRC/lcms
./autogen.sh
./configure \
  --enable-static \
  --disable-shared \
  --disable-dependency-tracking \
  --prefix=$WORK
make -j$(nproc)
make install
popd

# aom
pushd $SRC/aom
mkdir -p build/linux
cd build/linux
extra_libaom_flags='-DAOM_MAX_ALLOCABLE_MEMORY=536870912 -DDO_RANGE_CHECK_CLAMP=1'
cmake \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_INSTALL_PREFIX=$WORK \
  -DCONFIG_PIC=1 \
  -DENABLE_EXAMPLES=0 \
  -DENABLE_DOCS=0 \
  -DENABLE_TESTS=0 \
  -DENABLE_TOOLS=0 \
  -DCONFIG_SIZE_LIMIT=1 \
  -DDECODE_HEIGHT_LIMIT=12288 \
  -DDECODE_WIDTH_LIMIT=12288 \
  -DAOM_EXTRA_C_FLAGS="$extra_libaom_flags" \
  -DAOM_EXTRA_CXX_FLAGS="$extra_libaom_flags" \
  -DAOM_TARGET_CPU=generic \
  ../../
make clean
make -j$(nproc)
make install
popd

# libheif
pushd $SRC/libheif
cmake \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_INSTALL_PREFIX=$WORK \
  -DBUILD_SHARED_LIBS=FALSE \
  -DWITH_EXAMPLES=FALSE \
  -DENABLE_PLUGIN_LOADING=FALSE \
  .
make -j$(nproc)
make install
popd

# libjpeg-turbo
pushd $SRC/libjpeg-turbo
cmake \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_INSTALL_PREFIX=$WORK \
  -DENABLE_STATIC=TRUE \
  -DENABLE_SHARED=FALSE \
  -DWITH_TURBOJPEG=FALSE \
  .
make -j$(nproc)
make install
popd

# libpng
pushd $SRC/libpng
sed -ie 's/option WARNING /& disabled/' scripts/pnglibconf.dfa
autoreconf -fi
./configure \
  --prefix=$WORK \
  --disable-shared \
  --disable-dependency-tracking
make -j$(nproc)
make install
popd

# libspng
pushd $SRC/libspng
meson setup build --prefix=$WORK --libdir=lib --default-library=static --buildtype=debugoptimized \
  -Dstatic_zlib=true
ninja -C build
ninja -C build install
popd

# libwebp
pushd $SRC/libwebp
autoreconf -fi
./configure \
  --enable-libwebpdemux \
  --enable-libwebpmux \
  --disable-shared \
  --disable-jpeg \
  --disable-tiff \
  --disable-gif \
  --disable-wic \
  --disable-threading \
  --disable-dependency-tracking \
  --prefix=$WORK
make -j$(nproc)
make install
popd

# libtiff ... a bug in libtiff master as of 20 Nov 2019 means we have to 
# explicitly disable lzma
pushd $SRC/libtiff
autoreconf -fi
./configure \
  --disable-lzma \
  --disable-shared \
  --disable-dependency-tracking \
  --prefix=$WORK
make -j$(nproc)
make install
popd

# libimagequant
pushd $SRC/libimagequant
meson setup build --prefix=$WORK --libdir=lib --default-library=static --buildtype=debugoptimized
ninja -C build
ninja -C build install
popd

# cgif
pushd $SRC/cgif
meson setup build --prefix=$WORK --libdir=lib --default-library=static --buildtype=debugoptimized
ninja -C build
ninja -C build install
popd

# pdfium doesn't need fuzzing, but we want to fuzz the libvips/pdfium link
pushd $SRC/pdfium-latest
cp lib/* $WORK/lib
cp -r include/* $WORK/include
popd

# make a pdfium.pc that libvips can use ... the version number just needs to
# be higher than 4200 to satisfy libvips
cat > $WORK/lib/pkgconfig/pdfium.pc << EOF
  prefix=$WORK
  exec_prefix=\${prefix}
  libdir=\${exec_prefix}/lib
  includedir=\${prefix}/include
  Name: pdfium
  Description: pdfium
  Version: 4901
  Requires:
  Libs: -L\${libdir} -lpdfium
  Cflags: -I\${includedir}
EOF

# highway
pushd $SRC/highway
cmake \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_INSTALL_PREFIX=$WORK \
  -DBUILD_SHARED_LIBS=0 \
  -DBUILD_TESTING=0 \
  -DHWY_ENABLE_CONTRIB=0 \
  -DHWY_ENABLE_EXAMPLES=0 \
  -DHWY_ENABLE_TESTS=0 \
  .
make -j$(nproc)
make install
popd

# libvips
# Disable building man pages, gettext po files, tools, and tests
sed -i "/subdir('man')/{N;N;N;d;}" meson.build
meson setup build --prefix=$WORK --libdir=lib --prefer-static --default-library=static \
  -Ddeprecated=false -Dexamples=false -Dcplusplus=false -Dmodules=disabled \
  -Dcpp_link_args="$LDFLAGS -Wl,-rpath=\$ORIGIN/lib"
ninja -C build
ninja -C build install

# Copy fuzz executables to $OUT
find build/fuzz -maxdepth 1 -executable -type f -exec cp -v '{}' $OUT \;

# All shared libraries needed during fuzz target execution should be inside the $OUT/lib directory
mkdir -p $OUT/lib
cp $WORK/lib/*.so $OUT/lib

# Merge the seed corpus in a single directory, exclude files larger than 2k
mkdir -p fuzz/corpus
find \
  $SRC/afl-testcases/{gif*,jpeg*,png,tiff,webp}/full/images \
  fuzz/*_fuzzer_corpus \
  test/test-suite/images \
  -type f -size -2k \
  -exec bash -c 'hash=($(sha1sum {})); mv {} fuzz/corpus/$hash' \;
zip -jrq $OUT/seed_corpus.zip fuzz/corpus

# Link corpus
for fuzzer in fuzz/*_fuzzer.cc; do
  target=$(basename "$fuzzer" .cc)
  ln -sf "seed_corpus.zip" "$OUT/${target}_seed_corpus.zip"
done

# Copy options and dictionary files to $OUT
find fuzz -name '*_fuzzer.dict' -exec cp -v '{}' $OUT \;
find fuzz -name '*_fuzzer.options' -exec cp -v '{}' $OUT \;
