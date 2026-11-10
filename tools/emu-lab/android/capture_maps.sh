#!/system/bin/sh
# Run as root on the phone WHILE A GAME IS RUNNING in the emulator (not at the menu):
#     su -c "sh /sdcard/Download/capture_maps.sh <package> [out_dir]"
# e.g.  su -c "sh /sdcard/Download/capture_maps.sh org.mupen64plusae.v3.fzurita"
#
# Some emulators run the game in a separate process (e.g. "<package>:game"), so this captures EVERY process
# whose name starts with the package name, one file each. The report contains no game or ROM data: only
# mapping layout, resident sizes, mapped native libraries and ROM-looking open file names.
PKG="$1"; OUT="${2:-/sdcard/Download}"
[ -z "$PKG" ] && { echo "usage: capture_maps.sh <package> [out_dir]"; exit 1; }
LIST=$(ps -A -o PID,NAME 2>/dev/null | awk -v p="$PKG" 'NR>1 && index($2,p)==1 {print $1" "$2}')
[ -z "$LIST" ] && { echo "no process starting with $PKG is running"; exit 1; }
echo "$LIST" | while read PID NAME; do
  SAFE=$(echo "$NAME" | tr ':/' '__')
  F="$OUT/emu_layout_${SAFE}_$PID.txt"
  {
    echo "== process $NAME pid $PID  $(getprop ro.product.model) android $(getprop ro.build.version.release) abi $(getprop ro.product.cpu.abi)"
    echo "== native libraries mapped (not system/apex/vendor)"
    awk '$6 ~ /\.so/ && $6 !~ /^\/(system|apex|vendor|product|odm|system_ext)\// {n=split($6,a,"/"); print a[n]}' /proc/$PID/maps | sort -u | head -80
    echo "== ROM-looking / emulator files open"
    ls -l /proc/$PID/fd 2>/dev/null | awk '{print $NF}' | grep -i -E "\.(z64|n64|v64|rom|gba|nds|nes|sfc|smc|gb|gbc|md|bin|iso|cso|zip|7z|chd)$" | sort -u | head -20
    echo "== maps with resident size (kB): start-end perms offset path | rss privdirty"
    awk '/^[0-9a-f]+-[0-9a-f]+ /{ if(h!="")print h" | rss="rss" priv_dirty="pd; path=""; for(i=6;i<=NF;i++) path=path" "$i; h=$1" "$2" "$3" "path; rss=0; pd=0 }
         /^Rss:/{rss=$2} /^Private_Dirty:/{pd=$2} END{print h" | rss="rss" priv_dirty="pd}' /proc/$PID/smaps
  } > "$F" 2>&1
  echo "wrote $F  ($(grep -c . "$F") lines)"
done
