#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Olivares.AI
# SPDX-License-Identifier: AGPL-3.0-only
# Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.
# Run only through the lab wrapper, on a disposable overlay of the supplied image.
# This proves the real helper/native mechanism under enforcing policy. The portal
# client and engine writer are explicit identity fixtures, not a console proof.
# The quoted command substitutions run in the disposable guest, not this shell.
# shellcheck disable=SC2016
set -euo pipefail
base=${1:?read-only appliance qcow2 baseline}
mode=${2:-native}
if [[ $mode != native && $mode != prepare-console ]] || [[ $mode == prepare-console && ${BASH_SOURCE[0]} == "$0" ]]; then
 echo 'PROOF runner-mode-invalid FAIL'; exit 2
fi
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
[[ -f $base ]] || { echo 'PROOF baseline-missing FAIL'; exit 2; }
[[ -w /dev/kvm ]] || { echo 'PROOF kvm-not-writable FAIL'; exit 2; }
export TMPDIR="$root/.heavy-job-lab/tmp"
mkdir -p "$TMPDIR"
for tool in qemu-system-x86_64 qemu-img ssh ssh-keygen scp docker python3; do command -v "$tool" >/dev/null; done
job=$(mktemp -d "$TMPDIR/storage-native.XXXXXX")
qemu_pid=
base_image=docker.io/library/almalinux:10@sha256:ba31c3299856068f77bc10574cad51b0a4f6a3dafb882668656e1639bee63db6
base_present=false
if docker image inspect "$base_image" >/dev/null 2>&1; then base_present=true; fi
container=
cleanup(){
 status=$?
 if [[ -n $qemu_pid ]]; then kill "$qemu_pid" 2>/dev/null || true; wait "$qemu_pid" 2>/dev/null || true; fi
 if [[ -n $container ]]; then docker rm -f "$container" >/dev/null 2>&1 || true; fi
 if [[ $base_present == false ]]; then docker image rm "$base_image" >/dev/null 2>&1 || true; fi
 rm -rf "$job"
 exit "$status"
}
trap cleanup EXIT
trap 'exit 143' TERM INT
mkdir -p "$job/seed" "$job/policy" "$job/docker"
chmod 700 "$job"
(
 cd "$root/appliance"
 CGO_ENABLED=0 go build -p 2 -trimpath -o "$job/helper" ./layer/storage/olivares-portal-storage
 CGO_ENABLED=0 go build -p 2 -trimpath -o "$job/client" ./test/storage/nativeclient
)
cp "$root"/appliance/selinux/olivares.{te,fc,if} "$job/policy/"
container=$(docker run -d --rm -v "$job:/work" "$base_image" sleep infinity)
docker exec "$container" dnf -y --releasever=10.2 install make bzip2 xorriso-1.5.6-6.el10.x86_64 selinux-policy-devel-42.1.18-4.el10_2.4.noarch
docker exec --user "$(id -u):$(id -g)" -w /work/policy "$container" make -f /usr/share/selinux/devel/Makefile olivares.pp
docker exec "$container" rpm -q selinux-policy-devel selinux-policy
ssh-keygen -q -t ed25519 -N '' -f "$job/id"
ssh-keygen -q -t ed25519 -N '' -f "$job/host"
python3 - "$job" <<'PY'
import json,pathlib,sys
p=pathlib.Path(sys.argv[1]);key=(p/'id.pub').read_text().strip()
answers={'schema_version':'appliance-answers/v1','source':'nocloud','host':{'owner':'cloud-init','hostname':'storage.example.test','network':{'mode':'dhcp'},'time':{'timezone':'UTC','servers':['pool.ntp.org']},'ssh_authorized_keys':[key],'management_interfaces':['eth0']},'product':{'storage_profile':'single-node-prod','public_console_url':'https://storage.example.test','update_channel':'stable','node_role':'control'},'portal':{'enabled':False,'listen':'local'}}
user={'fqdn':'storage.example.test','users':[{'name':'storageproof','sudo':'ALL=(ALL) NOPASSWD:ALL','groups':['wheel'],'shell':'/bin/bash','ssh_authorized_keys':[key]}],'ssh_pwauth':False,'ssh_keys':{'ed25519_private':(p/'host').read_text(),'ed25519_public':(p/'host.pub').read_text().strip()},'write_files':[{'path':'/etc/olivares-appliance/carriers/nocloud.json','permissions':'0600','owner':'root:root','content':json.dumps(answers)}]}
(p/'seed/user-data').write_text('#cloud-config\n'+json.dumps(user));(p/'seed/meta-data').write_text('instance-id: storage-native-proof\nlocal-hostname: storage.example.test\n')
(p/'seed/network-config').write_text(json.dumps({'version':2,'renderer':'NetworkManager','ethernets':{'eth0':{'match':{'macaddress':'52:54:00:30:37:01'},'set-name':'eth0','dhcp4':True}}}))
PY
docker exec --user "$(id -u):$(id -g)" "$container" xorriso -as mkisofs -quiet -output /work/seed.iso -volid cidata -joliet -rock /work/seed
qemu-img create -q -f qcow2 -F qcow2 -b "$base" "$job/guest.qcow2"
qemu-img create -q -f qcow2 "$job/backup.qcow2" 20G
start_guest(){
 port=$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')
 printf '[127.0.0.1]:%s %s\n' "$port" "$(cat "$job/host.pub")" >> "$job/known_hosts"
 rm -f "$job/qmp"
 qemu-system-x86_64 -accel kvm -cpu host -m 4096 -smp 2 -display none -serial "file:$job/serial.log" -qmp "unix:$job/qmp,server=on,wait=off" -drive "file=$job/guest.qcow2,id=root,if=virtio,format=qcow2" -drive "file=$job/backup.qcow2,id=backup,if=virtio,format=qcow2" -drive "file=$job/seed.iso,media=cdrom,readonly=on" -netdev "user,id=control,hostfwd=tcp:127.0.0.1:$port-:22" -device virtio-net-pci,netdev=control,mac=52:54:00:30:37:01 > "$job/qemu.out" 2> "$job/qemu.err" &
 qemu_pid=$!
 ssh_args=(-i "$job/id" -p "$port" -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=3 -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$job/known_hosts" storageproof@127.0.0.1)
 scp_args=(-i "$job/id" -P "$port" -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$job/known_hosts")
 ready=false
 for _ in $(seq 1 90); do if ssh "${ssh_args[@]}" true 2> "$job/ssh.err"; then ready=true; break; fi; kill -0 "$qemu_pid" || break; sleep 2; done
 [[ $ready == true ]] || { echo 'PROOF guest-ssh FAIL'; exit 2; }
}
# Arguments are fixed guest shell programs supplied by this proof runner.
# shellcheck disable=SC2029
remote(){ ssh "${ssh_args[@]}" "$@"; }
probe(){
 remote "sudo bash -s -- $1" <<'CLIENT'
set -euo pipefail
mode=$1
case "$mode" in inventory|guard-root|backup|grow) ;; *) exit 2;; esac
systemctl stop olivares-portal.service 2>/dev/null || true
cat > /run/systemd/system/olivares-portal.service <<UNIT
[Service]
Type=oneshot
User=olivares-portal
Group=olivares-portal
NoNewPrivileges=yes
ExecStart=/usr/libexec/olivares/native-storage-proof $mode
StandardOutput=journal
StandardError=journal
UNIT
mkdir -p /run/systemd/system/olivares-portal.service.d
cat > /run/systemd/system/olivares-portal.service.d/99-native-proof.conf <<'UNIT'
[Service]
# Override the image's host-operations drop-in: failed proof effects run once.
Restart=no
UNIT
systemctl daemon-reload
if ! systemctl start olivares-portal.service; then
 journalctl -u olivares-portal.service -n 25 --no-pager -o cat >&2
 journalctl -b -u 'olivares-helper-storage@*' -n 40 --no-pager -o cat >&2
 journalctl -b --grep 'avc:.*denied|SELinux policy denies' -n 60 --no-pager -o cat >&2
 exit 1
fi
invocation=$(systemctl show -p InvocationID --value olivares-portal.service)
journalctl "_SYSTEMD_INVOCATION_ID=$invocation" --no-pager -o cat
CLIENT
}
start_guest
remote 'test "$(getenforce)" = Enforcing; mkdir -p /var/tmp/storage-native-proof'
scp "${scp_args[@]}" "$job/helper" "$job/client" "$job/policy/olivares.pp" "$root/appliance/images/kiwi/almalinux10-server-amd64/etc/olivares-appliance/image" "$root/appliance/layer/storage/units/olivares-grow-data@.service" "$root/appliance/layer/storage/units/olivares-helper-storage.socket" "$root/appliance/layer/storage/units/olivares-helper-storage@.service" storageproof@127.0.0.1:/var/tmp/storage-native-proof/
remote 'sudo bash -s' <<'GUEST'
set -euo pipefail
cd /var/tmp/storage-native-proof
semodule -i olivares.pp
install -m 0755 helper /usr/libexec/olivares/olivares-portal-storage
install -m 0755 client /usr/libexec/olivares/native-storage-proof
install -m 0755 client /usr/libexec/olivares/native-storage-writer
install -m 0644 olivares-grow-data@.service olivares-helper-storage.socket olivares-helper-storage@.service /usr/lib/systemd/system/
install -d -m 0755 /mnt/olivares-backups /etc/olivares-appliance
install -m 0644 -o root -g root image /etc/olivares-appliance/image
restorecon -RF /usr/libexec/olivares/olivares-portal-storage /usr/lib/systemd/system/olivares-grow-data@.service /mnt/olivares-backups /etc/olivares-appliance/image
chcon -t olivares_portal_exec_t /usr/libexec/olivares/native-storage-proof
chcon -t olivares_exec_t /usr/libexec/olivares/native-storage-writer
systemctl daemon-reload
systemctl restart olivares-helper-storage.socket
systemctl enable olivares-grow-data@auto.service
getenforce
GUEST
if [[ $mode == prepare-console ]]; then return 0; fi
before=$(remote 'df -B1 --output=size / | tail -1' | tr -d '[:space:]')
probe inventory > "$job/inventory-initial.json"
probe guard-root
remote 'sudo poweroff' || true
wait "$qemu_pid" || true
qemu_pid=
qemu-img resize -q "$job/guest.qcow2" 16G
start_guest
remote 'test "$(getenforce)" = Enforcing; test "$(systemctl show -p Result --value olivares-grow-data@auto.service)" = success'
auto=$(remote 'df -B1 --output=size / | tail -1' | tr -d '[:space:]')
[[ $auto -gt $((before+3*1024*1024*1024)) ]] || { echo "PROOF automatic-grow FAIL before=$before after=$auto"; remote 'sudo journalctl -u olivares-grow-data@auto.service --no-pager -o cat'; exit 1; }
echo "PROOF automatic-grow PASS before=$before after=$auto enforcing=yes"
remote 'sudo systemd-run --quiet --collect --unit=storage-proof-writer.service --uid=olivares --gid=olivares -p ProtectSystem=full -p PrivateDevices=yes -p NoNewPrivileges=yes /usr/libexec/olivares/native-storage-writer wait-write'
probe backup > "$job/backup-result.json"
for _ in $(seq 1 45); do if remote 'sudo journalctl -u storage-proof-writer.service --no-pager -o cat' | grep -qx WRITER_PASS; then writer=true; break; fi; sleep 1; done
[[ ${writer:-false} == true ]] || { echo 'PROOF late-mounted-engine-write FAIL'; remote 'sudo ausearch -m AVC -ts recent | tail -40'; exit 1; }
remote 'sudo python3 -' <<'PYBACKUP'
import os,pwd,stat,subprocess
found=[]
for line in open('/etc/fstab'):
 fields=line.split()
 if len(fields)>=4 and fields[1].startswith('/mnt/olivares-backups/'):
  found.append(fields)
assert len(found)==1, 'exactly one owned backup mount expected'
f=found[0];assert f[0]=='UUID='+f[1].rsplit('/',1)[1] and f[2]=='ext4'
assert {'nofail','nodev','nosuid','noexec'} <= set(f[3].split(','))
st=os.stat(f[1]);assert st.st_uid==pwd.getpwnam('olivares').pw_uid and stat.S_IMODE(st.st_mode)==0o700
assert subprocess.check_output(['findmnt','-n','-o','FSTYPE','--target',f[1]],text=True).strip()=='ext4'
assert b':olivares_backups_t:' in os.getxattr(f[1],'security.selinux')
print('BACKUP_TARGET_VALIDATED')
PYBACKUP
echo 'PROOF backup-disk PASS ext4=yes uuid=yes nofail=yes owner=olivares mode=0700 late-engine-namespace=yes identity=fixture'
python3 - "$job/qmp" <<'PY'
import json,socket,sys
s=socket.socket(socket.AF_UNIX);s.connect(sys.argv[1]);f=s.makefile('rwb',buffering=0)
def command(name,args=None):
 f.write((json.dumps({'execute':name,**({'arguments':args} if args else {})})+'\n').encode())
 while True:
  r=json.loads(f.readline())
  if 'error' in r:raise RuntimeError(r['error'])
  if 'return' in r:return r['return']
json.loads(f.readline());command('qmp_capabilities');command('block_resize',{'device':'root','size':20*1024**3});s.close()
PY
for _ in $(seq 1 20); do size=$(remote 'sudo blockdev --getsize64 /dev/vda'); [[ $size == 21474836480 ]] && break; sleep 1; done
[[ $size == 21474836480 ]]
probe grow > "$job/grow-result.json"
grown=$(remote 'df -B1 --output=size / | tail -1' | tr -d '[:space:]')
[[ $grown -gt $((auto+3*1024*1024*1024)) ]] || { echo "PROOF manual-grow FAIL before=$auto after=$grown"; exit 1; }
echo "PROOF manual-grow PASS before=$auto after=$grown reboot=no enforcing=yes"
probe guard-root
remote 'test "$(getenforce)" = Enforcing; sudo lsblk -b -o NAME,SIZE,FSTYPE,MOUNTPOINTS; sudo findmnt -n -o SOURCE,FSTYPE,TARGET /'
sha256sum "$job/helper" "$job/policy/olivares.pp"
echo 'PROOF native-storage-mechanism PASS console-and-scheduled-backup=not-run identity=fixture'
