#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Olivares.AI
# SPDX-License-Identifier: AGPL-3.0-only
# Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.
# Run through heavy-job --lab. Credentials exist only in the disposable guest/job.
# The quoted command substitutions run in the disposable guest, not this shell.
# shellcheck disable=SC2016
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
bin="$root/.heavy-job-lab/console"
mkdir -p "$bin"
for tool in go node pnpm; do
 command -v "$tool" >/dev/null || { echo "UNAVAILABLE storage console proof: missing $tool"; exit 2; }
done
pnpm --dir web install --frozen-lockfile
pnpm --dir web exec playwright install chromium
CGO_ENABLED=0 go build -p 2 -trimpath -o "$bin/olivares" ./cmd/olivares
(cd appliance && CGO_ENABLED=0 go build -p 2 -trimpath -o "$bin/portal" ./layer/portal/cmd/olivares-portal)
# Keep the enforcing guest and the single cleanup trap for the console proof.
# shellcheck source=appliance/test/storage/run-native.sh
source "$root/appliance/test/storage/run-native.sh" "${1:?read-only baseline}" prepare-console
probe guard-root
initial_size=$(remote 'df -B1 --output=size / | tail -1' | tr -d '[:space:]')
remote 'sudo poweroff' || true
wait "$qemu_pid" || true
qemu_pid=
qemu-img resize -q "$job/guest.qcow2" 16G
start_guest
for _ in $(seq 1 60); do
 automatic_size=$(remote 'df -B1 --output=size / | tail -1' | tr -d '[:space:]')
 [[ $automatic_size -gt $((initial_size+3*1024*1024*1024)) ]] && break
 sleep 1
done
[[ $automatic_size -gt $((initial_size+3*1024*1024*1024)) ]] || { echo "PROOF console-next-boot-grow FAIL before=$initial_size after=$automatic_size"; remote 'sudo journalctl -u olivares-grow-data@auto.service --no-pager -o cat'; exit 1; }
remote 'test "$(getenforce)" = Enforcing; test "$(systemctl show -p Result --value olivares-grow-data@auto.service)" = success'
echo "PROOF console-next-boot-grow PASS before=$initial_size after=$automatic_size enforcing=yes"
qemu-img create -q -f qcow2 "$job/console-backup.qcow2" 20G
python3 - "$job/qmp" "$job/console-backup.qcow2" <<'PY'
import json,socket,sys
s=socket.socket(socket.AF_UNIX);s.connect(sys.argv[1]);f=s.makefile('rwb',buffering=0);json.loads(f.readline())
def cmd(name,args=None):
 f.write((json.dumps({'execute':name,**({'arguments':args} if args else {})})+'\n').encode())
 while True:
  r=json.loads(f.readline())
  if 'error' in r:raise RuntimeError(r['error'])
  if 'return' in r:return
cmd('qmp_capabilities');cmd('blockdev-add',{'driver':'qcow2','node-name':'console-backup','file':{'driver':'file','filename':sys.argv[2]}});cmd('device_add',{'driver':'virtio-blk-pci','drive':'console-backup','id':'console-backup-device'});cmd('block_resize',{'device':'root','size':20*1024**3})
PY
scp "${scp_args[@]}" "$bin/olivares" "$bin/portal" storageproof@127.0.0.1:/var/tmp/storage-native-proof/
remote 'sudo bash -s' <<'GUEST'
set -euo pipefail
umask 0077
systemctl stop olivares.service olivares-portal.service
rm -f /run/systemd/system/olivares-portal.service
rm -f /run/systemd/system/olivares-portal.service.d/99-native-proof.conf
install -m 0755 /var/tmp/storage-native-proof/olivares /usr/bin/olivares
install -m 0755 /var/tmp/storage-native-proof/portal /usr/libexec/olivares/olivares-portal
restorecon /usr/bin/olivares /usr/libexec/olivares/olivares-portal
install -d -o olivares -g olivares -m 0750 /var/lib/olivares
install -d -m 0755 /run/systemd/system/olivares.service.d
cat > /run/systemd/system/olivares.service.d/storage-proof.conf <<'UNIT'
[Service]
ExecStart=
ExecStart=/usr/bin/olivares serve --data-dir=/var/lib/olivares --engine=sqlite --listen=127.0.0.1:8443 --grpc-listen=127.0.0.1:8444
UNIT
systemctl daemon-reload
systemctl restart olivares.service
for n in $(seq 1 300); do
 test -s /var/lib/olivares/public/tls.crt && break
 systemctl is-active --quiet olivares.service || break
 sleep 1
done
if ! test -s /var/lib/olivares/public/tls.crt; then
 systemctl show -p ActiveState -p Result -p ExecStart olivares.service
 journalctl -u olivares.service -b --no-pager -o cat | python3 -c 'import sys,re;rows=[s for s in sys.stdin if not re.search(r"olst_|password|passphrase|token|private.key|dsn",s,re.I) and re.search(r"error|denied|panic|failed|refus",s,re.I)];print("".join(rows[-15:]))'
 # A stuck disposable process supplies function names and source locations only.
 # Never print its raw arguments or the unfiltered product journal.
 main_pid=$(systemctl show -p MainPID --value olivares.service)
 if [[ $main_pid =~ ^[1-9][0-9]*$ ]]; then
  kill -QUIT "$main_pid"
  sleep 2
  journalctl -u olivares.service -b --no-pager -o cat | python3 -c 'import sys,re
active=False;count=0
for line in sys.stdin:
 if re.match(r"goroutine [0-9]+ ",line):
  active=count<20;count+=1
  if active:print(line.rstrip())
 elif active and re.match(r"^\S+\(",line):print(line.split("(",1)[0])
 elif active and re.match(r"^\s+\S+\.go:[0-9]+",line):print(line.split(" +0x",1)[0].rstrip())'
 fi
 ausearch -m AVC -ts recent | tail -30 || true
 exit 1
fi
sudo -u olivares /usr/bin/olivares first-boot --data-dir=/var/lib/olivares --new-token > /var/tmp/storage-native-proof/setup-output
chmod 0600 /var/tmp/storage-native-proof/setup-output
# Supply an operator-owned certificate pair through the production credential unit.
install -d -m 0755 /etc/olivares-portal
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=storage.example.test -addext subjectAltName=IP:127.0.0.1 -keyout /etc/olivares-portal/tls.key -out /etc/olivares-portal/tls.crt >/dev/null 2>&1
chmod 0600 /etc/olivares-portal/tls.key
chmod 0644 /etc/olivares-portal/tls.crt
restorecon -RF /etc/olivares-portal
systemctl daemon-reload
systemctl restart olivares-portal.socket
systemctl start olivares-portal.service
python3 - <<'PY'
import json,ssl,urllib.request,subprocess,re,secrets,pathlib,time
p=pathlib.Path('/var/lib/olivares');ctx=ssl.create_default_context(cafile=str(p/'public/tls.crt'))
for n in range(120):
 try:
  urllib.request.urlopen('https://127.0.0.1:8443/v1/server-info',context=ctx,timeout=3);break
 except Exception:time.sleep(1)
log=pathlib.Path('/var/tmp/storage-native-proof/setup-output').read_text()
tokens=re.findall(r'olst_[A-Z0-9]+',log);assert tokens,'new installation must publish a setup token'
password=secrets.token_urlsafe(32)
recovery=pathlib.Path('/var/tmp/storage-native-proof/recovery.key');recovery.write_bytes((p/'dr-recovery.key').read_bytes());recovery.chmod(0o600)
body=json.dumps({'token':tokens[-1],'email':'storage-proof@example.test','password':password,'backup_key_saved':True}).encode()
r=urllib.request.urlopen(urllib.request.Request('https://127.0.0.1:8443/v1/setup',data=body,headers={'Content-Type':'application/json'}),context=ctx);assert r.status==201
# Save the recovery key outside the guest data volume without printing it.
auth=pathlib.Path('/var/tmp/storage-native-proof/browser.json');auth.write_text(json.dumps({'email':'storage-proof@example.test','password':password}));auth.chmod(0o600)
PY
chown storageproof:storageproof /var/tmp/storage-native-proof/browser.json /var/tmp/storage-native-proof/recovery.key
GUEST
scp "${scp_args[@]}" storageproof@127.0.0.1:/var/tmp/storage-native-proof/browser.json storageproof@127.0.0.1:/var/tmp/storage-native-proof/recovery.key "$job/"
# SSH forwards to the guest's own loopback; host-side browser never reaches a wildcard guest port.
webport=$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')
ssh "${ssh_args[@]}" -N -L "127.0.0.1:$webport:127.0.0.1:9443" &
tunnel_pid=$!
console_cleanup(){
 status=$?
 trap - EXIT
 kill "$tunnel_pid" 2>/dev/null || true
 wait "$tunnel_pid" 2>/dev/null || true
 set +e
 (exit "$status")
 cleanup
}
trap console_cleanup EXIT
mkdir -p "$root/storage-console-proof"
console_before=$(remote 'df -B1 --output=size / | tail -1' | tr -d '[:space:]')
if ! node "$root/appliance/test/storage/console-browser.mjs" "https://127.0.0.1:$webport" "$job/browser.json" "$root/storage-console-proof"; then
 remote 'sudo python3 -' <<'DIAGNOSTICS'
import pathlib,json,ssl,urllib.request,http.cookiejar,subprocess,re,datetime
p=pathlib.Path('/var/lib/olivares');ctx=ssl.create_default_context(cafile=str(p/'public/tls.crt'));jar=http.cookiejar.CookieJar();client=urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx),urllib.request.HTTPCookieProcessor(jar))
def req(path,body=None):
 headers={'Content-Type':'application/json','X-Olivares-Session':'cookie'}
 if 'csrf' in globals():headers['X-CSRF-Token']=csrf
 r=client.open(urllib.request.Request('https://127.0.0.1:8443'+path,data=None if body is None else json.dumps(body).encode(),headers=headers));return json.load(r)
try:
 req('/v1/auth/login',json.loads(pathlib.Path('/var/tmp/storage-native-proof/browser.json').read_text()));csrf=req('/v1/auth/browser-session')['csrf_token'];who=req('/v1/auth/whoami')
 reply=req('/v1/console/appliance/storage/authorize',{'task':'storage.backup','target':'drive:'+'a'*64,'intent_digest':'b'*64})
 print('CORE_STORAGE_AUTHORIZATION',json.dumps({'allowed':reply.get('allowed'),'actor_matches':reply.get('actor')==who.get('actor'),'valid_until':reply.get('valid_until')}))
except urllib.error.HTTPError as e:print('CORE_STORAGE_AUTHORIZATION_HTTP',e.code)
logs=subprocess.check_output(['journalctl','-u','olivares.service','-u','olivares-portal.service','-u','olivares-helper-storage@*','-b','--no-pager','-o','cat'],text=True)
for line in logs.splitlines():
 if re.search(r'olst_|password|passphrase|token|private.key|dsn',line,re.I):continue
 if re.search(r'storage/authorize|console/dr/schedule|published selection|stopped:|error|denied|panic|failed|refus',line,re.I):print(line)
print(subprocess.check_output(['lsblk','-b','-o','NAME,SIZE,FSTYPE,MOUNTPOINTS'],text=True))
for path in pathlib.Path('/var/lib/olivares-portal/operations').glob('*.json'):
 try:
  record=json.loads(path.read_text()).get('record',{})
  print('STORAGE_OPERATION',json.dumps({key:record.get(key) for key in ['operation_id','task_id','state','outcome']}))
 except (OSError,ValueError):print('STORAGE_OPERATION_UNREADABLE')
for path in pathlib.Path('/var/lib/olivares-portal').rglob('records.jsonl'):
 for line in path.read_text().splitlines():
  try:record=json.loads(line)
  except ValueError:continue
  if str(record.get('verb','')).startswith('storage'):
   print('STORAGE_AUDIT',json.dumps({key:record.get(key) for key in ['operation_id','verb','outcome']}))
avcs=subprocess.run(['ausearch','-m','AVC,USER_AVC','-ts','boot'],text=True,capture_output=True).stdout
for line in avcs.splitlines():
 if 'denied' in line and not re.search(r'olst_|password|passphrase|token|private.key|dsn',line,re.I):print(line)
DIAGNOSTICS
 exit 1
fi
remote 'sudo python3 -' <<'PY'
import pathlib,json,ssl,urllib.request,http.cookiejar,time
p=pathlib.Path('/var/lib/olivares');ctx=ssl.create_default_context(cafile=str(p/'public/tls.crt'));jar=http.cookiejar.CookieJar();client=urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx),urllib.request.HTTPCookieProcessor(jar))
def req(path,body=None,method=None):
 headers={'Content-Type':'application/json','X-Olivares-Session':'cookie'}
 if 'csrf' in globals():headers['X-CSRF-Token']=csrf
 r=client.open(urllib.request.Request('https://127.0.0.1:8443'+path,data=None if body is None else json.dumps(body).encode(),headers=headers,method=method));return json.load(r)
req('/v1/auth/login',json.loads(pathlib.Path('/var/tmp/storage-native-proof/browser.json').read_text()));csrf=req('/v1/auth/browser-session')['csrf_token']
sched=req('/v1/console/dr/schedule');prior_run=sched.get('last_run');target=sched['local_target'];assert target.startswith('/mnt/olivares-backups/');assert sched['cron']=='0 2 * * *'
# Exercise the persisted schedule pump now, then restore the nightly schedule.
update={key:sched[key] for key in ['enabled','retain_days','verify_cron','rpo_hours'] if key in sched};update['cron']='* * * * *'
req('/v1/console/dr/schedule',update,'PUT')
for n in range(180):
 s=req('/v1/console/dr/schedule')
 if s.get('last_run')!=prior_run and s.get('last_run_status')=='completed':break
 if s.get('last_run')!=prior_run and s.get('last_run_status')=='failed':raise RuntimeError(s.get('last_run_error'))
 time.sleep(1)
else:raise RuntimeError('scheduler did not complete within three minutes')
assert list(pathlib.Path(target).glob('*.drbundle')), 'scheduled bundle missing from selected disk'
update['cron']='0 2 * * *';req('/v1/console/dr/schedule',update,'PUT');print('PROOF console-scheduled-backup PASS target=selected-ext4 nightly=restored')
PY
console_after=$(remote 'df -B1 --output=size / | tail -1' | tr -d '[:space:]')
[[ $console_after -gt $((console_before+3*1024*1024*1024)) ]] || { echo "PROOF console-online-grow FAIL before=$console_before after=$console_after"; exit 1; }
echo "PROOF console-online-grow PASS before=$console_before after=$console_after reboot=no"
remote 'test "$(getenforce)" = Enforcing; sudo findmnt -n -o SOURCE,FSTYPE,TARGET /mnt/olivares-backups/*'
# Leave the hot-added backup disk absent on the next boot as a real nofail check.
remote 'sudo poweroff' || true
wait "$qemu_pid" || true
qemu_pid=
start_guest
remote 'test "$(getenforce)" = Enforcing; test ! -b /dev/vdc'
echo 'PROOF backup-nofail-boot PASS selected-backup-disk=absent boot=yes enforcing=yes'
sha256sum "$bin/olivares" "$bin/portal" "$job/helper" "$job/policy/olivares.pp"
echo 'PROOF storage-console PASS real-product=yes real-portal=yes enforcing=yes'
