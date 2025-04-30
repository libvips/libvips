#!/bin/bash -eu

export PKG_CONFIG="pkg-config --static"
export PKG_CONFIG_PATH="$WORK/lib/pkgconfig"
export CPPFLAGS="-I$WORK/include"
export LDFLAGS="-L$WORK/lib"

# `-fuse-ld=gold` can't be passed via `CFLAGS` and `CXXFLAGS` as Meson
# injects `-Werror=ignored-optimization-argument` during compile tests.
# https://github.com/google/oss-fuzz/issues/12167
# https://github.com/mesonbuild/meson/issues/6377#issuecomment-575977919
if [[ "$CFLAGS" == *"-fuse-ld=gold"* ]]; then
  export CFLAGS="${CFLAGS//-fuse-ld=gold/}"
  export CC_LD=gold
fi
if [[ "$CXXFLAGS" == *"-fuse-ld=gold"* ]]; then
  export CXXFLAGS="${CXXFLAGS//-fuse-ld=gold/}"
  export CXX_LD=gold
fi

# Run as many parallel jobs as there are available CPU cores
export MAKEFLAGS="-j$(nproc)"

# libz
pushd $SRC/zlib
./configure --static --prefix=$WORK
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
make install doc_DATA=
popd

# lcms
pushd $SRC/lcms
meson setup build --prefix=$WORK --libdir=lib --default-library=static --buildtype=debugoptimized \
  -Dtests=disabled -Djpeg=disabled -Dtiff=disabled
meson install -C build --tag devel
popd

# aom
pushd $SRC/aom
mkdir -p build/linux
cd build/linux
extra_libaom_flags='-DAOM_MAX_ALLOCABLE_MEMORY=536870912 -DDO_RANGE_CHECK_CLAMP=1'
cmake \
  -GNinja \
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
cmake --build . --target install
popd

# libheif
pushd $SRC/libheif
cmake \
  -GNinja \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_INSTALL_PREFIX=$WORK \
  -DBUILD_SHARED_LIBS=FALSE \
  -DBUILD_TESTING=FALSE \
  -DWITH_EXAMPLES=FALSE \
  -DENABLE_PLUGIN_LOADING=FALSE \
  .
cmake --build . --target install
popd

# libjpeg-turbo
pushd $SRC/libjpeg-turbo
cmake \
  -GNinja \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_INSTALL_PREFIX=$WORK \
  -DENABLE_STATIC=TRUE \
  -DENABLE_SHARED=FALSE \
  -DWITH_TURBOJPEG=FALSE \
  .
cmake --build . --target jpeg-static
cmake --install . --component lib
cmake --install . --component include
popd

# libspng
pushd $SRC/libspng
meson setup build --prefix=$WORK --libdir=lib --default-library=static --buildtype=debugoptimized \
  -Dstatic_zlib=true -Dbuild_examples=false
meson install -C build --tag devel
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
make install bin_PROGRAMS= noinst_PROGRAMS= man_MANS=
popd

# libtiff ... a bug in libtiff master as of 20 Nov 2019 means we have to
# explicitly disable lzma
pushd $SRC/libtiff
autoreconf -fi
./configure \
  --disable-tools \
  --disable-tests \
  --disable-contrib \
  --disable-docs \
  --disable-lzma \
  --disable-shared \
  --disable-dependency-tracking \
  --prefix=$WORK
make install noinst_PROGRAMS= dist_doc_DATA=
popd

# libimagequant
pushd $SRC/libimagequant
meson setup build --prefix=$WORK --libdir=lib --default-library=static --buildtype=debugoptimized
meson install -C build --tag devel
popd

# cgif
pushd $SRC/cgif
meson setup build --prefix=$WORK --libdir=lib --default-library=static --buildtype=debugoptimized \
  -Dexamples=false -Dtests=false
meson install -C build --tag devel
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
libdir=\${prefix}/lib
includedir=\${prefix}/include

Name: pdfium
Description: pdfium
Version: 4901
Libs: -L\${libdir} -lpdfium
Cflags: -I\${includedir}
EOF

# highway
pushd $SRC/highway
cmake \
  -GNinja \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_INSTALL_PREFIX=$WORK \
  -DBUILD_SHARED_LIBS=0 \
  -DBUILD_TESTING=0 \
  -DHWY_ENABLE_CONTRIB=0 \
  -DHWY_ENABLE_EXAMPLES=0 \
  -DHWY_ENABLE_TESTS=0 \
  .
cmake --build . --target install
popd

# FIXME: Workaround for https://github.com/mesonbuild/meson/issues/14533
export LDFLAGS+=" $CFLAGS"

# libvips
# Disable building man pages, gettext po files, tools, and tests
sed -i "/subdir('man')/{N;N;N;d;}" meson.build
meson setup build --prefix=$WORK --libdir=lib --prefer-static --default-library=static --buildtype=debugoptimized \
  -Ddeprecated=false -Dexamples=false -Dcplusplus=false -Dmodules=disabled \
  -Dfuzzing_engine=oss-fuzz -Dfuzzer_ldflags="$LIB_FUZZING_ENGINE" \
  -Dcpp_link_args="$LDFLAGS -Wl,-rpath=\$ORIGIN/lib"
meson install -C build --tag devel

# Copy fuzz executables to $OUT
find build/fuzz -maxdepth 1 -executable -type f -exec cp -v '{}' $OUT \;

# All shared libraries needed during fuzz target execution should be inside the $OUT/lib directory
mkdir -p $OUT/lib
cp $WORK/lib/*.so $OUT/lib

# Merge the seed corpus in a single directory, exclude files larger than 4k
mkdir -p fuzz/corpus
find \
  $SRC/afl-testcases/{gif*,jpeg*,png,tiff,webp}/full/images \
  fuzz/*_fuzzer_corpus \
  test/test-suite/images \
  -type f -size -4k \
  -exec bash -c 'hash=($(sha1sum {})); mv {} fuzz/corpus/$hash' \;
zip -jrq $OUT/seed_corpus.zip fuzz/corpus

# Link corpus
for fuzzer in $OUT/*_fuzzer; do
  target=$(basename "$fuzzer")
  ln -sf "seed_corpus.zip" "$OUT/${target}_seed_corpus.zip"
done

# Copy options and dictionary files to $OUT
find fuzz -name '*_fuzzer.dict' -exec cp -v '{}' $OUT \;
find fuzz -name '*_fuzzer.options' -exec cp -v '{}' $OUT \;
