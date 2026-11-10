#!/bin/sh
# Builds the headless lab: stub libs for what the bundle expects but this box lacks, the no-op plugins, the host.
set -e
BUNDLE="${1:-/home/claude/emu/mupen64plus-bundle-linux64-2.6.0}"
OUT="${2:-/tmp/emulab-build}"
HERE="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$OUT/stubs"
echo "" > "$OUT/empty.c"
for lib in libminizip.so.1 libGLU.so.1 libOpenGL.so.0 libspeexdsp.so.1; do
  [ -f "$OUT/stubs/$lib" ] || gcc -shared -o "$OUT/stubs/$lib" -Wl,-soname,"$lib" "$OUT/empty.c"
done
for kind in VIDEO AUDIO INPUT; do
  lc=$(echo $kind | tr A-Z a-z)
  gcc -O1 -shared -fPIC -fvisibility=hidden -D PLUGIN_$kind -I"$BUNDLE/api" -o "$OUT/emulab-$lc.so" "$HERE/dummy_plugins.c"
done
gcc -O1 -I"$BUNDLE/api" -o "$OUT/m64p_host" "$HERE/m64p_host.c" -ldl -lpthread
echo "built in $OUT"
