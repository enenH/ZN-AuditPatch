#!/system/bin/sh

MODDIR=/data/adb/modules/auditpatch

if [ -f "$MODDIR/disable" ] || [ -f "$MODDIR/remove" ]; then
    exit 0
fi

"$MODDIR"/bin/daemon &
