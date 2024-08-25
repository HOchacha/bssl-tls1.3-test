#!/usr/bin/env bash
function symlink_to_dir() {
if [[ -z "$1" ]]; then
echo "arg 1 to symlink_to_dir is unexpectedly empty"
exit 1
fi
if [[ -z "$2" ]]; then
echo "arg 2 to symlink_to_dir is unexpectedly empty"
exit 1
fi
local target="$2"
mkdir -p "$target"
if [[ -f "$1" ]]; then
# In order to be able to use `replace_in_files`, we ensure that we create copies of specfieid
# files so updating them is possible.
if [[ "$1" == *.pc || "$1" == *.la || "$1" == *-config || "$1" == *.mk || "$1" == *.cmake ]]; then
dest="$target/$(basename "$1")"
cp "$1" "$dest" && chmod +w "$dest" && touch -r "$1" "$dest"
else
ln -sf "$1" "$target/${1##*/}"
fi
elif [[ -L "$1" && ! -d "$1" ]]; then
cp -pR "$1" "$2"
elif [[ -d "$1" ]]; then
SAVEIFS=$IFS
IFS=$'
'
local children=($(find -H "$1" -maxdepth 1 -mindepth 1))
IFS=$SAVEIFS
local dirname=$(basename "$1")
mkdir -p "$target/$dirname"
for child in "${children[@]:-}"; do
if [[ -n "$child" && "$dirname" != *.ext_build_deps ]]; then
symlink_to_dir "$child" "$target/$dirname"
fi
done
else
echo "Can not copy $1"
fi
}
function children_to_path() {
if [ -d $EXT_BUILD_DEPS/bin ]; then
local tools=$(find "$EXT_BUILD_DEPS/bin" -maxdepth 1 -mindepth 1)
for tool in $tools;
do
if  [[ -d "$tool" ]] || [[ -L "$tool" ]]; then
export PATH=$PATH:$tool
fi
done
fi
}
function replace_in_files() {
if [ -d "$1" ]; then
SAVEIFS=$IFS
IFS=$'
'
# Find all real files. Symlinks are assumed to be relative to something within the directory we're seaching and thus ignored
local files=($(find -P "$1" \( -type f -and \( -name "*.pc" -or -name "*.la" -or -name "*-config" -or -name "*.mk" -or -name "*.cmake" \) \)))
IFS=$SAVEIFS
for file in ${files[@]+"${files[@]}"}; do
local backup=$(mktemp)
touch -r "${file}" "${backup}"
sed -i 's@'"$2"'@'"$3"'@g' "${file}"
if [[ "$?" -ne "0" ]]; then
exit 1
fi
touch -r "${backup}" "${file}"
rm "${backup}"
done
fi
}
echo """"
echo ""Bazel external C/C++ Rules. Building library 'bssl-compat'""
echo """"
set -euo pipefail
export EXT_BUILD_ROOT=$(pwd)
export INSTALLDIR=$EXT_BUILD_ROOT/bazel-out/k8-fastbuild/bin/bssl-compat/bssl-compat
export BUILD_TMPDIR=$INSTALLDIR.build_tmpdir
export EXT_BUILD_DEPS=$INSTALLDIR.ext_build_deps
export Clang_ROOT="/usr/lib/llvm"
export PATH="$EXT_BUILD_ROOT:$PATH"
rm -rf $BUILD_TMPDIR
rm -rf $EXT_BUILD_DEPS
mkdir -p $INSTALLDIR
mkdir -p $BUILD_TMPDIR
mkdir -p $EXT_BUILD_DEPS
echo ""Environment:______________""
env
echo ""__________________________""
mkdir -p $EXT_BUILD_DEPS/bin
symlink_to_dir $EXT_BUILD_ROOT/external/cmake-3.23.2-linux-x86_64/bin $EXT_BUILD_DEPS/bin/
symlink_to_dir $EXT_BUILD_ROOT/bazel-out/k8-opt-exec-2B5CBBC6/bin/external/rules_foreign_cc/toolchains $EXT_BUILD_DEPS/bin/
children_to_path $EXT_BUILD_DEPS/bin
export PATH="$EXT_BUILD_DEPS/bin:$PATH"
cd $BUILD_TMPDIR
export CC="/opt/llvm/bin/clang-14"
export CXX="/opt/llvm/bin/clang-14"
export CFLAGS="-U_FORTIFY_SOURCE -fstack-protector -Wall -Wthread-safety -Wself-assign -Wunused-but-set-parameter -Wno-free-nonheap-object -fcolor-diagnostics -fno-omit-frame-pointer -no-canonical-prefixes -Wno-builtin-macro-redefined -D__DATE__=\\\"redacted\\\" -D__TIMESTAMP__=\\\"redacted\\\" -D__TIME__=\\\"redacted\\\" -DABSL_MIN_LOG_LEVEL=4 -fPIC -Wno-deprecated-declarations -fexceptions"
export CXXFLAGS="-U_FORTIFY_SOURCE -fstack-protector -Wall -Wthread-safety -Wself-assign -Wunused-but-set-parameter -Wno-free-nonheap-object -fcolor-diagnostics -fno-omit-frame-pointer -std=c++0x -no-canonical-prefixes -Wno-builtin-macro-redefined -D__DATE__=\\\"redacted\\\" -D__TIMESTAMP__=\\\"redacted\\\" -D__TIME__=\\\"redacted\\\" -DABSL_MIN_LOG_LEVEL=4 -fPIC -Wno-deprecated-declarations -std=c++17"
export ASMFLAGS="-U_FORTIFY_SOURCE -fstack-protector -Wall -Wthread-safety -Wself-assign -Wunused-but-set-parameter -Wno-free-nonheap-object -fcolor-diagnostics -fno-omit-frame-pointer -no-canonical-prefixes -Wno-builtin-macro-redefined -D__DATE__=\\\"redacted\\\" -D__TIMESTAMP__=\\\"redacted\\\" -D__TIME__=\\\"redacted\\\" -DABSL_MIN_LOG_LEVEL=4 -fPIC -Wno-deprecated-declarations -fexceptions"
export Clang_ROOT="/usr/lib/llvm"
set -x
$EXT_BUILD_ROOT/external/cmake-3.23.2-linux-x86_64/bin/cmake -DCMAKE_AR="/usr/bin/ar" -DCMAKE_SHARED_LINKER_FLAGS="-shared -fuse-ld=/opt/llvm/bin/ld.lld -Wl,-no-as-needed -Wl,-z,relro,-z,now -B/opt/llvm/bin -lm -l:libstdc++.a -fuse-ld=lld -L/opt/llvm/lib -Wl,-rpath,/opt/llvm/lib" -DCMAKE_EXE_LINKER_FLAGS="-fuse-ld=/opt/llvm/bin/ld.lld -Wl,-no-as-needed -Wl,-z,relro,-z,now -B/opt/llvm/bin -lm -l:libstdc++.a -fuse-ld=lld -L/opt/llvm/lib -Wl,-rpath,/opt/llvm/lib" -DCMAKE_BUILD_TYPE="Release" -DCMAKE_INSTALL_PREFIX="$INSTALLDIR" -DCMAKE_PREFIX_PATH="$EXT_BUILD_DEPS" -DCMAKE_RANLIB="" -DCMAKE_MAKE_PROGRAM=$EXT_BUILD_ROOT/bazel-out/k8-opt-exec-2B5CBBC6/bin/external/rules_foreign_cc/toolchains/make/bin/make -G 'Unix Makefiles' $EXT_BUILD_ROOT/bssl-compat
$EXT_BUILD_ROOT/external/cmake-3.23.2-linux-x86_64/bin/cmake --build . --config Release  -j
$EXT_BUILD_ROOT/external/cmake-3.23.2-linux-x86_64/bin/cmake --install . --config Release 
set +x
replace_in_files $INSTALLDIR $BUILD_TMPDIR \${EXT_BUILD_DEPS}
replace_in_files $INSTALLDIR $EXT_BUILD_DEPS \${EXT_BUILD_DEPS}
replace_in_files $INSTALLDIR $EXT_BUILD_ROOT \${EXT_BUILD_ROOT}
mkdir -p $EXT_BUILD_ROOT/bazel-out/k8-fastbuild/bin/bssl-compat/copy_bssl-compat/bssl-compat
cp -L -r --no-target-directory "$INSTALLDIR" "$EXT_BUILD_ROOT/bazel-out/k8-fastbuild/bin/bssl-compat/copy_bssl-compat/bssl-compat" && find "$EXT_BUILD_ROOT/bazel-out/k8-fastbuild/bin/bssl-compat/copy_bssl-compat/bssl-compat" -type f -exec touch -r "$INSTALLDIR" "{}" \;
cd $EXT_BUILD_ROOT
if [[ -L "bazel-out/k8-fastbuild/bin/bssl-compat/bssl-compat/lib/libbssl-compat.a" ]]; then
  target="$(readlink -f "bazel-out/k8-fastbuild/bin/bssl-compat/bssl-compat/lib/libbssl-compat.a")"
  rm "bazel-out/k8-fastbuild/bin/bssl-compat/bssl-compat/lib/libbssl-compat.a" && cp -a "${target}" "bazel-out/k8-fastbuild/bin/bssl-compat/bssl-compat/lib/libbssl-compat.a"
fi

