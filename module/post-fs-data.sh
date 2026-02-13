#!/system/bin/sh
MODDIR=${0%/*}
KO="$MODDIR/hymofs_lkm.ko"
if [ -f "$KO" ]; then
  chmod 0644 "$KO"
  /system/bin/insmod "$KO" >/dev/null 2>&1 || insmod "$KO" >/dev/null 2>&1
fi
