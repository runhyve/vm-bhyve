#!/bin/sh
# Run with FreeBSD sh, or bash on macOS. No root or ZFS required.
set -e
. ./lib/vm-crypt

fail(){ printf 'FAIL: %s\n' "$*" >&2; exit 1; }
util::warn(){ printf '%s\n' "$*" >&2; }
config::yesno(){ return 1; }
work=$(mktemp -d "${TMPDIR:-/tmp}/vm-crypt-test.XXXXXXXX")
trap 'rm -rf "$work"' EXIT

# Unsafe paths must fail before writing any material.
crypt::__safe_directory /tmp/../vm-crypt-key && fail 'accepted parent traversal'
crypt::__safe_directory /tmp/vm-crypt-key && fail 'accepted unsafe ancestor'

# Verify trap isolation and status preservation, including a failed unload.
zfs(){ printf '%s\n' "$*" >> "$work/calls"; return 1; }
set +e
(crypt::creation_begin; VM_CRYPT_CREATED='pool/test/newdisk'; exit 7)
result=$?
set -e
[ "$result" = 7 ] || fail 'cleanup changed failure status'
[ "$(cat "$work/calls")" = 'unload-key pool/test/newdisk' ] || fail 'wrong cleanup target'
rm "$work/calls"
(crypt::creation_begin; VM_CRYPT_CREATED='pool/test/newdisk'; VM_CRYPT_CREATE_KEEP=yes; exit 0)
[ ! -e "$work/calls" ] || fail 'keep-loaded ignored'

# Exercise actual mktemp/chmod/link publication. Bypass ownership validation
# only here, since the test directory belongs to the invoking non-root user.
crypt::__file_check(){ return 0; }
crypt::__publish_key "$work/key" || fail 'publication failed'
[ "$(wc -c < "$work/key" | tr -d ' ')" = 65 ] || fail 'invalid generated key length'
cp "$work/key" "$work/original"
crypt::__publish_key "$work/key" && fail 'overwrote existing key'
cmp "$work/key" "$work/original" || fail 'existing key changed'
ln -s "$work/missing" "$work/symlink"
crypt::__publish_key "$work/symlink" && fail 'followed dangling symlink'
[ ! -e "$work/missing" ] || fail 'wrote through symlink'
mkdir "$work/directory"
crypt::__publish_key "$work/directory" && fail 'published into destination directory'

# Failed random generation must not publish or leave a temporary key.
openssl(){ return 1; }
crypt::__publish_key "$work/failed" && fail 'accepted generation failure'
[ ! -e "$work/failed" ] || fail 'published failed generation'
for file in "$work"/.vm-key.*; do
    [ ! -e "$file" ] || fail 'temporary secret left behind'
done

# Suspend checks must use storage even when the configuration flag is absent.
datastore::get_guest(){ VM_DS_PATH="$work"; VM_DS_ZFS=1; VM_DS_ZFS_DATASET=pool; }
config::load(){ :; }
zfs(){ printf '%s\n' aes-256-gcm; }
crypt::suspend_allowed guest && fail 'accepted encrypted storage'
zfs(){ printf '%s\n' off; }
crypt::suspend_allowed guest || fail 'rejected unencrypted storage'
config::yesno(){ return 0; }
crypt::suspend_allowed guest && fail 'accepted encryption flag'

# Exercise the actual add_disk error exit after a successful ZVOL create.
. ./lib/vm-core
util::err(){ exit 1; }
setvar(){ eval "$1=\$2"; }
config::get(){
    case "$2" in
        disk0_name) setvar "$1" disk0 ;;
        disk0_type) setvar "$1" virtio-blk ;;
        *) setvar "$1" '' ;;
    esac
}
config::yesno(){ [ "$1" = encryption ]; }
config::set(){ return 1; }
zfs::make_zvol(){ VM_CRYPT_CREATED="${VM_CRYPT_CREATED} $1"; }
zfs(){ printf '%s\n' "$*" >> "$work/add-calls"; }
set +e
core::add_disk guest sparse-zvol 1G
result=$?
set -e
[ "$result" = 1 ] || fail 'add config failure did not fail'
[ "$(cat "$work/add-calls")" = 'unload-key pool/guest/disk1' ] || fail 'add unloaded an existing disk'

# suspendall must preflight the whole set before invoking suspend at all.
util::check_bhyve_suspend(){ return 0; }
cmd::parse_args(){ :; }
pgrep(){ printf '10 bhyve: plain\n11 bhyve: encrypted\n'; }
crypt::suspend_allowed(){ [ "$1" = plain ]; }
core::suspend(){ touch "$work/suspended"; }
core::suspendall && fail 'suspendall accepted mixed targets'
[ ! -e "$work/suspended" ] || fail 'suspendall partially suspended guests'
printf 'P1 regression checks passed\n'
