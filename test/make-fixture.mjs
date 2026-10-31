// Builds the replay fixtures (test/fixtures/<name>/commands.json) that stand in for real phones:
//
//   infected       Samsung One UI, Android 13. One known stalkerware app (com.systemservice, on the
//                  Echap list as TheTruthSpy), one hidden home-made RAT, one normal Play-installed app,
//                  system apps, an updated system app with its factory copy under "Hidden system
//                  packages:", and a debloated app that is installed for no user.
//   legacy-xiaomi  Xiaomi MIUI, Android 7.1 (no `cmd package`): userId=, flags= + pkgFlags=, CRLF line
//                  endings from the old adb pty, a MIUI "dual apps" user 999, a package without
//                  `requested permissions:`, a spy app whose launcher activity is disabled, old toolbox ps.
//   work-pixel     Pixel, Android 14: appId=, InstallSource{...} / installInitiator=, a work profile
//                  (user 10) holding an app installed only there, split APKs, a stub system app, a
//                  TV-launcher-only app, role holders, adb-server noise and two phones in `adb devices`,
//                  and a malformed package block that must not swallow its neighbour.
//
// Formats follow real `dumpsys` output as closely as we know it; they are UNPROVEN against every
// OEM build until recorded from real phones (`guardian scan --record DIR`).
import { writeFileSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), 'fixtures');
const P = 'android.permission.';

/**
 * One `Package [...]` block.
 * style: 'a13' (default, the original fixture format), 'a7' (Android 7/8: userId=, package-level
 * firstInstallTime) or 'a14' (appId=, per-user firstInstallTime, installer lines from `installerLines`).
 * users: [{ id, installed, enabled, hidden, runtime: [perm], disabled: [cls] }] (default: user 0, installed).
 * requested: null leaves the `requested permissions:` section out entirely.
 */
function pkgBlock({
  pkg, path, uid, installer, system = false, updatedSystem = false, debuggable = false, requested = [], granted = [], runtime = [],
  first = '2023-01-10 09:00:00', version = '1.0', style = 'a13', users = null, splits = null, installerLines = null, sharedUser = null,
}) {
  const flagList = [...(system ? ['SYSTEM'] : []), ...(updatedSystem ? ['UPDATED_SYSTEM_APP'] : []), ...(debuggable ? ['DEBUGGABLE'] : []), 'HAS_CODE', system ? 'ALLOW_CLEAR_USER_DATA' : 'ALLOW_BACKUP'];
  const flags = flagList.join(' ');
  const userList = users || [{ id: 0, installed: true, runtime }];
  const idLine = style === 'a7' ? `userId=${uid}` : `appId=${uid}`;
  const installerBlock = installerLines ?? [`installerPackageName=${installer ?? 'null'}`];
  const userBlock = (u) => {
    const installed = u.installed !== false;
    const head = style === 'a7'
      ? `    User ${u.id}: ceDataInode=${installed ? 4711 : 0} installed=${installed} hidden=${!!u.hidden} suspended=false stopped=false notLaunched=false enabled=${u.enabled ?? 0} instant=false`
      : `    User ${u.id}: ceDataInode=${installed ? 4711 : 0} installed=${installed} hidden=${!!u.hidden} suspended=false distractionFlags=0 stopped=false notLaunched=false enabled=${u.enabled ?? 0} instant=false virtual=false`;
    const lines = [head];
    if (style === 'a14') lines.push('      installReason=0', `      firstInstallTime=${u.first || first}`, '      uninstallReason=0');
    if (style !== 'a7') lines.push('      lastDisabledCaller: null');
    lines.push('      gids=[3003]');
    if (u.runtime && u.runtime.length) {
      lines.push('      runtime permissions:');
      for (const p of u.runtime) lines.push(style === 'a7' ? `        ${p}: granted=true, flags=[ USER_SET ]` : `        ${p}: granted=true, flags=[ USER_SET|USER_SENSITIVE_WHEN_GRANTED ]`);
      for (const p of u.denied || []) lines.push(`        ${p}: granted=false, flags=[ USER_SET ]`);
    }
    if (u.disabled && u.disabled.length) {
      lines.push('      disabledComponents:');
      for (const c of u.disabled) lines.push(`        ${c}`);
    }
    return lines.join('\n');
  };
  const out = [
    `  Package [${pkg}] (a1b2c3):`,
    `    ${idLine}`,
    ...(sharedUser ? [`    sharedUser=SharedUserSetting{5e6f7a ${sharedUser}}`] : []),
    `    pkg=Package{1234 ${pkg}}`,
    `    codePath=${path}`,
    `    resourcePath=${path}`,
    '    primaryCpuAbi=null',
    `    versionCode=1 minSdk=23 targetSdk=${style === 'a7' ? 25 : 33}`,
    `    versionName=${version}`,
    ...(splits ? [`    splits=[${splits.join(', ')}]`] : []),
    `    flags=[ ${flags} ]`,
    '    privateFlags=[ PRIVATE_FLAG_ALLOW_AUDIO_PLAYBACK_CAPTURE ]',
    `    dataDir=/data/user/0/${pkg}`,
    '    timeStamp=2023-01-10 09:00:00',
    ...(style === 'a14' ? [] : [`    firstInstallTime=${first}`]),
    '    lastUpdateTime=2023-01-10 09:00:00',
    ...installerBlock.map((l) => `    ${l}`),
    '    signatures=PackageSignatures{abc version:3, signatures:[xyz], past signatures:[]}',
    '    installPermissionsFixed=true',
    `    pkgFlags=[ ${flags} ]`,
  ];
  if (requested) {
    out.push('    requested permissions:');
    for (const p of requested) out.push(`      ${p}`);
  }
  if (granted.length || style !== 'a7') {
    out.push('    install permissions:');
    for (const p of granted) out.push(`      ${p}: granted=true`);
  }
  for (const u of userList) out.push(userBlock(u));
  return out.join('\n') + '\n';
}

function write(name, commands) {
  const dir = join(root, name);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'commands.json'), JSON.stringify(commands, null, 1));
  console.log(`fixture written: ${join(dir, 'commands.json')} (${Object.keys(commands).length} commands)`);
}

const ROLE_CMD = 'shell for r in SMS DIALER ASSISTANT HOME; do echo "$r=$(cmd role get-role-holders android.app.role.$r 2>&1)"; done';
const LAUNCHER = 'shell cmd package query-activities --brief -a android.intent.action.MAIN -c android.intent.category.LAUNCHER';
const LEANBACK = 'shell cmd package query-activities --brief -a android.intent.action.MAIN -c android.intent.category.LEANBACK_LAUNCHER';

// =============================================================================================
// infected: Samsung, Android 13
// =============================================================================================
{
  const packages = [
    pkgBlock({ pkg: 'com.android.settings', path: '/system_ext/priv-app/Settings', uid: 1000, system: true, requested: [P + 'WRITE_SECURE_SETTINGS'], granted: [P + 'WRITE_SECURE_SETTINGS'] }),
    // Updated system app: the live copy is in /data/app; the factory copy shows up again below
    // under "Hidden system packages:" and must not overwrite this record.
    pkgBlock({ pkg: 'com.android.vending', path: '/data/app/~~vnd==/com.android.vending-pq==', uid: 10050, system: true, updatedSystem: true, requested: [P + 'INTERNET'], granted: [P + 'INTERNET'] }),
    pkgBlock({ pkg: 'com.google.android.marvin.talkback', path: '/product/app/talkback', uid: 10060, system: true, requested: [P + 'BIND_ACCESSIBILITY_SERVICE'] }),
    pkgBlock({
      pkg: 'com.whatsapp', path: '/data/app/~~abc==/com.whatsapp-xyz==', uid: 10200, installer: 'com.android.vending',
      requested: [P + 'RECORD_AUDIO', P + 'CAMERA', P + 'READ_CONTACTS', P + 'ACCESS_FINE_LOCATION', P + 'READ_EXTERNAL_STORAGE', P + 'INTERNET'],
      granted: [P + 'INTERNET'], runtime: [P + 'RECORD_AUDIO', P + 'CAMERA', P + 'READ_CONTACTS'], first: '2022-05-01 12:00:00', version: '2.24.1',
      splits: ['base', 'config.arm64_v8a', 'config.xxhdpi'],
    }),
    // Known stalkerware: package name is on the Echap list (TheTruthSpy family).
    pkgBlock({
      pkg: 'com.systemservice', path: '/data/app/~~def==/com.systemservice-abc==', uid: 10301, installer: null,
      requested: [P + 'RECORD_AUDIO', P + 'READ_SMS', P + 'RECEIVE_SMS', P + 'READ_CALL_LOG', P + 'ACCESS_FINE_LOCATION', P + 'ACCESS_BACKGROUND_LOCATION', P + 'READ_CONTACTS', P + 'SYSTEM_ALERT_WINDOW', P + 'BIND_ACCESSIBILITY_SERVICE', P + 'RECEIVE_BOOT_COMPLETED', P + 'INTERNET'],
      granted: [P + 'SYSTEM_ALERT_WINDOW', P + 'RECEIVE_BOOT_COMPLETED', P + 'INTERNET'],
      runtime: [P + 'RECORD_AUDIO', P + 'READ_SMS', P + 'RECEIVE_SMS', P + 'READ_CALL_LOG', P + 'ACCESS_FINE_LOCATION', P + 'ACCESS_BACKGROUND_LOCATION', P + 'READ_CONTACTS'],
      first: '2026-10-20 23:41:00', version: '7.2',
    }),
    // Home-made RAT: not on any list, so only behaviour can catch it.
    pkgBlock({
      pkg: 'com.wifi.update.service', path: '/data/app/~~ghi==/com.wifi.update.service-qqq==', uid: 10302, installer: 'com.google.android.packageinstaller',
      requested: [P + 'RECORD_AUDIO', P + 'CAMERA', P + 'READ_SMS', P + 'READ_CALL_LOG', P + 'ACCESS_FINE_LOCATION', P + 'READ_CONTACTS', P + 'SYSTEM_ALERT_WINDOW', P + 'REQUEST_INSTALL_PACKAGES', P + 'RECEIVE_BOOT_COMPLETED', P + 'INTERNET'],
      granted: [P + 'SYSTEM_ALERT_WINDOW', P + 'REQUEST_INSTALL_PACKAGES', P + 'INTERNET'],
      runtime: [P + 'RECORD_AUDIO', P + 'CAMERA', P + 'READ_SMS', P + 'READ_CALL_LOG', P + 'ACCESS_FINE_LOCATION', P + 'READ_CONTACTS'],
      first: '2026-10-25 02:10:00', version: '1.0',
    }),
    // Plain sideloaded game: should stay OK or WATCH at most.
    pkgBlock({ pkg: 'org.supertuxkart.stk', path: '/data/app/~~jkl==/org.supertuxkart.stk-rrr==', uid: 10303, installer: 'org.fdroid.fdroid', requested: [P + 'INTERNET', P + 'VIBRATE'], granted: [P + 'INTERNET', P + 'VIBRATE'] }),
    // Debloated with `pm uninstall --user 0`: still in the dump, installed for nobody. Not an app on the phone.
    pkgBlock({ pkg: 'com.samsung.android.bixby.agent', path: '/system/priv-app/BixbyAgentStub', uid: 10110, system: true, requested: [P + 'RECORD_AUDIO'], users: [{ id: 0, installed: false }] }),
  ];
  const hidden = [
    pkgBlock({ pkg: 'com.android.vending', path: '/product/priv-app/Phonesky', uid: 10050, system: true, requested: [P + 'INTERNET'], granted: [P + 'INTERNET'] }),
  ];

  write('infected', {
    'devices -l': 'List of devices attached\nR58M12ABCDE            device product:a52 model:SM_A525F device:a52q transport_id:3\n',
    'shell getprop ro.product.model': 'SM-A525F\n',
    'shell getprop ro.product.manufacturer': 'samsung\n',
    'shell getprop ro.build.version.release': '13\n',
    'shell getprop ro.build.version.sdk': '33\n',
    'shell getprop ro.build.version.security_patch': '2024-03-01\n',
    'shell getprop ro.build.tags': 'release-keys\n',
    'shell getprop ro.boot.verifiedbootstate': 'green\n',
    'shell getprop ro.boot.flash.locked': '1\n',
    'shell getprop ro.debuggable': '0\n',
    'shell which su*': '',
    'shell settings get global adb_enabled': '1\n',
    'shell settings get global development_settings_enabled': '1\n',
    'shell settings get secure install_non_market_apps': 'null\n',
    'shell settings get global package_verifier_enable': '0\n',
    'shell settings get global verifier_verify_adb_installs': '1\n',
    'shell settings get global private_dns_mode': 'opportunistic\n',
    'shell settings get global private_dns_specifier': 'null\n',
    'shell settings get secure default_input_method': 'com.samsung.android.honeyboard/.service.HoneyBoardService\n',
    'shell settings get secure sms_default_application': 'com.samsung.android.messaging\n',
    'shell settings get global stay_on_while_plugged_in': '0\n',
    'shell date +%s': '1793400000\n',
    'shell pm list users': 'Users:\n\tUserInfo{0:Owner:c13} running\n',
    'shell settings get secure enabled_accessibility_services': 'com.systemservice/com.systemservice.AccService:com.google.android.marvin.talkback/com.google.android.marvin.talkback.TalkBackService\n',
    'shell settings get secure enabled_notification_listeners': 'com.wifi.update.service/.NotifService\n',
    'shell settings get secure accessibility_shortcut_target_service': 'com.systemservice/com.systemservice.AccService\n',
    'shell settings get secure accessibility_button_targets': 'com.android.server.accessibility.MagnificationController\n',
    'shell dumpsys device_policy': `Current Device Policy Manager state:
  Immutable state:
    mHasFeature=true
  Enabled Device Admins (User 0, provisioningState: 0):
    com.systemservice/.DevAdminReceiver:
      uid=10301
      testOnlyAdmin=false
      policies:
        force-lock
        wipe-data
      passwordQuality=0x0
  Password Owner: -1
`,
    'shell dumpsys deviceidle whitelist': 'system-excidle,com.android.vending,10050\nuser,com.systemservice,10301\nuser,com.wifi.update.service,10302\n',
    [LAUNCHER]: `1 activities found:
  com.android.settings/.Settings
  com.whatsapp/.Main
  org.supertuxkart.stk/.SuperTuxKartActivity
  com.android.vending/.AssetBrowserActivity
`,
    [LEANBACK]: 'No activities found\n',
    'shell appops query-op GET_USAGE_STATS allow*': 'com.systemservice\n',
    [ROLE_CMD]: 'SMS=com.samsung.android.messaging\nDIALER=com.samsung.android.dialer\nASSISTANT=\nHOME=com.sec.android.app.launcher\n',
    'shell ls /data/misc/user/0/cacerts-added 2>&1': 'ls: /data/misc/user/0/cacerts-added: Permission denied\n',
    'shell dumpsys notification': `Current Notification Manager state:
  Notification List:
    NotificationRecord(0x0a1b2c3d: pkg=com.whatsapp user=UserHandle{0} id=1 tag=null importance=4 key=0|com.whatsapp|1|null|10200: Notification(channel=msg))
  Notification listeners:
    Allowed user profiles: {0}
    Default Allowed: []
    All notification listeners (2) enabled for current profiles:
      com.android.systemui/com.android.systemui.statusbar.notification.NotificationListener
      com.wifi.update.service/com.wifi.update.service.NotifService
    Live notification listeners (2):
      com.android.systemui/com.android.systemui.statusbar.notification.NotificationListener (user 0): ManagedServiceInfo[component=ComponentInfo{com.android.systemui/com.android.systemui.statusbar.notification.NotificationListener},userid=0,isSystem=true]
      com.wifi.update.service/com.wifi.update.service.NotifService (user 0): ManagedServiceInfo[component=ComponentInfo{com.wifi.update.service/com.wifi.update.service.NotifService},userid=0,isSystem=false]
  Notification assistant services:
    Allowed user profiles: {0}
`,
    'shell dumpsys package packages': `Packages:\n${packages.join('\n')}\nHidden system packages:\n${hidden.join('\n')}`,
    'shell sha256sum *': `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  /data/app/~~abc==/com.whatsapp-xyz==/base.apk
bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  /data/app/~~def==/com.systemservice-abc==/base.apk
cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc  /data/app/~~ghi==/com.wifi.update.service-qqq==/base.apk
dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd  /data/app/~~jkl==/org.supertuxkart.stk-rrr==/base.apk
`,
    'shell dumpsys netstats detail': `Active interfaces:
  ident=[{type=WIFI}] iface=wlan0
UID stats:
  ident=[{type=WIFI}] uid=10200 set=DEFAULT tag=0x0
    NetworkStatsHistory: bucketDuration=7200
      st=1793300000 rb=104857600 rp=1000 tb=52428800 tp=800 op=0
  ident=[{type=WIFI}] uid=10301 set=DEFAULT tag=0x0
    NetworkStatsHistory: bucketDuration=7200
      st=1793300000 rb=2048000 rp=400 tb=734003200 tp=90000 op=0
`,
    'shell ps -A -o NAME*': `NAME
init
system_server
com.android.systemui
com.systemservice
com.wifi.update.service
com.whatsapp
`,
  });
}

// =============================================================================================
// legacy-xiaomi: Xiaomi MIUI, Android 7.1.2 (sdk 25). No `cmd package`; CRLF output.
// =============================================================================================
{
  const crlf = (s) => s.replace(/\n/g, '\r\n');
  const packages = [
    pkgBlock({ style: 'a7', pkg: 'com.miui.home', path: '/system/priv-app/MiuiHome', uid: 10030, system: true, requested: [P + 'INTERNET'], granted: [P + 'INTERNET'] }),
    pkgBlock({ style: 'a7', pkg: 'com.android.settings', path: '/system/priv-app/Settings', uid: 1000, system: true, sharedUser: 'android.uid.system/1000', requested: [P + 'WRITE_SECURE_SETTINGS'], granted: [P + 'WRITE_SECURE_SETTINGS'] }),
    // Installed from the Xiaomi store, also cloned into MIUI "dual apps" (user 999) with fewer grants there.
    pkgBlock({
      style: 'a7', pkg: 'com.whatsapp', path: '/data/app/com.whatsapp-1', uid: 10120, installer: 'com.xiaomi.market',
      requested: [P + 'RECORD_AUDIO', P + 'CAMERA', P + 'INTERNET'], granted: [P + 'INTERNET'], first: '2019-03-02 08:00:00',
      users: [{ id: 0, runtime: [P + 'CAMERA'] }, { id: 999, runtime: [P + 'RECORD_AUDIO'] }],
    }),
    // Spy app that hid its icon by disabling its launcher activity (still in the resolver table).
    pkgBlock({
      style: 'a7', pkg: 'com.android.sys.helper', path: '/data/app/com.android.sys.helper-2', uid: 10150, installer: null, debuggable: true,
      requested: [P + 'READ_SMS', P + 'ACCESS_FINE_LOCATION', P + 'RECORD_AUDIO', P + 'INTERNET'], granted: [P + 'INTERNET'],
      first: '2026-10-28 01:00:00', users: [{ id: 0, runtime: [P + 'READ_SMS', P + 'ACCESS_FINE_LOCATION', P + 'RECORD_AUDIO'], disabled: ['com.android.sys.helper.MainActivity'] }],
    }),
    // No `requested permissions:` section at all (an app that asks for nothing).
    pkgBlock({ style: 'a7', pkg: 'com.example.flashlight', path: '/data/app/com.example.flashlight-1', uid: 10160, installer: 'com.android.vending', requested: null }),
    // Disabled by the user (enabled=3), and hidden by the system.
    pkgBlock({ style: 'a7', pkg: 'com.facebook.appmanager', path: '/system/app/FBAppManager', uid: 10170, system: true, requested: [P + 'INTERNET'], users: [{ id: 0, enabled: 3, hidden: true }] }),
  ];
  write('legacy-xiaomi', {
    'devices -l': '* daemon not running; starting now at tcp:5037\r\n* daemon started successfully\r\nList of devices attached\r\n4f3c2b1a               device usb:1-4 product:santoni model:Redmi_4X device:santoni transport_id:1\r\n',
    'shell getprop ro.product.model': 'Redmi 4X\r\n',
    'shell getprop ro.product.manufacturer': 'Xiaomi\r\n',
    'shell getprop ro.build.version.release': '7.1.2\r\n',
    'shell getprop ro.build.version.sdk': '25\r\n',
    'shell getprop ro.build.version.security_patch': '2019-02-01\r\n',
    'shell getprop ro.build.tags': 'release-keys\r\n',
    'shell settings get secure sms_default_application': 'com.android.mms\r\n',
    'shell settings get secure dialer_default_application': 'com.android.contacts\r\n',
    'shell settings get secure assistant': 'com.google.android.googlequicksearchbox/com.google.android.voiceinteraction.GsaVoiceInteractionService\r\n',
    'shell settings get global stay_on_while_plugged_in': '3\r\n',
    'shell pm list users': 'Users:\r\n\tUserInfo{0:机主:13} running\r\n\tUserInfo{999:XSpace:801010} running\r\n',
    'shell settings get secure enabled_accessibility_services': 'com.android.sys.helper/com.android.sys.helper.Acc\r\n',
    'shell settings --user 999 get secure enabled_accessibility_services': 'null\r\n',
    'shell settings get secure enabled_notification_listeners': 'null\r\n',
    // `cmd` exists on 7.x but this OEM build lacks the query: falls back to the resolver table.
    [LAUNCHER]: "Error: unknown command 'query-activities'\r\n",
    'shell dumpsys package r activity': crlf(`
Activity Resolver Table:
  Non-Data Actions:
      android.intent.action.MAIN:
        2c4a1e0 com.miui.home/.launcher.Launcher filter 7d1b9a2
          Action: "android.intent.action.MAIN"
          Category: "android.intent.category.HOME"
          Category: "android.intent.category.DEFAULT"
        3b8c7d1 com.android.settings/.Settings filter 1f2e3d4
          Action: "android.intent.action.MAIN"
          Category: "android.intent.category.LAUNCHER"
          Category: "android.intent.category.DEFAULT"
        4c9d8e2 com.whatsapp/.Main filter 2a3b4c5
          Action: "android.intent.action.MAIN"
          Category: "android.intent.category.LAUNCHER"
        5dae9f3 com.android.sys.helper/.MainActivity filter 3b4c5d6
          Action: "android.intent.action.MAIN"
          Category: "android.intent.category.LAUNCHER"
        6ebfa04 com.example.flashlight/.Light filter 4c5d6e7
          Action: "android.intent.action.MAIN"
          Category: "android.intent.category.LAUNCHER"
      android.intent.action.VIEW:
        7fc0b15 com.android.sys.helper/.Viewer filter 5d6e7f8
          Action: "android.intent.action.VIEW"
          Category: "android.intent.category.LAUNCHER"

Receiver Resolver Table:
  Non-Data Actions:
      android.intent.action.MAIN:
        8ad1c26 com.facebook.appmanager/.Recv filter 6e7f809
          Action: "android.intent.action.MAIN"
          Category: "android.intent.category.LAUNCHER"
`),
    'shell dumpsys package packages': crlf(`Packages:\n${packages.join('\n')}`),
    'shell sha256sum *': crlf(`1111111111111111111111111111111111111111111111111111111111111111  /data/app/com.whatsapp-1/base.apk
2222222222222222222222222222222222222222222222222222222222222222  /data/app/com.android.sys.helper-2/base.apk
`),
    'shell ls /data/misc/user/0/cacerts-added 2>&1': '9a5ba575.0\r\nc8750f0d.0\r\n',
    'shell ps -A -o NAME*': crlf(`bad pid '-o'
USER      PID   PPID  VSIZE  RSS   WCHAN              PC  NAME
root      1     0     23456  1234  SyS_epoll_ 0000000000 S /init
system    812   1     1890000 98000 SyS_epoll_ 0000000000 S system_server
u0_a150   4242  600   1700000 45000 SyS_epoll_ 0000000000 S com.android.sys.helper:remote
u0_a120   4300  600   1800000 60000 SyS_epoll_ 0000000000 S com.whatsapp
`),
  });
}

// =============================================================================================
// work-pixel: Pixel 8, Android 14 (sdk 34), personal + work profile, two phones attached.
// =============================================================================================
{
  const packages = [
    pkgBlock({ style: 'a14', pkg: 'com.google.android.apps.nexuslauncher', path: '/system_ext/priv-app/NexusLauncherRelease', uid: 10090, system: true, requested: [P + 'INTERNET'], granted: [P + 'INTERNET'], users: [{ id: 0 }, { id: 10 }] }),
    // Updated system app; factory copy in "Hidden system packages:".
    pkgBlock({ style: 'a14', pkg: 'com.google.android.gms', path: '/data/app/~~gms==/com.google.android.gms-zz==', uid: 10100, system: true, updatedSystem: true, requested: [P + 'INTERNET'], granted: [P + 'INTERNET'], users: [{ id: 0 }, { id: 10 }] }),
    // System stub: the real camera app is downloaded on first use.
    pkgBlock({ style: 'a14', pkg: 'com.google.android.GoogleCamera', path: '/product/app/GoogleCamera-Stub', uid: 10110, system: true, requested: [P + 'CAMERA'] }),
    // Play install recorded only through installInitiator= (no installerPackageName line).
    pkgBlock({
      style: 'a14', pkg: 'com.spotify.music', path: '/data/app/~~sp==/com.spotify.music-aa==', uid: 10220,
      installerLines: ['installInitiator=com.android.vending', 'packageSource=0'], requested: [P + 'INTERNET', P + 'RECORD_AUDIO'], granted: [P + 'INTERNET'],
      splits: ['base', 'config.arm64_v8a', 'config.en', 'config.xxhdpi'], users: [{ id: 0, runtime: [], denied: [P + 'RECORD_AUDIO'] }],
    }),
    // Browser download: installer only inside an InstallSource{...} block.
    pkgBlock({
      style: 'a14', pkg: 'com.free.vpn.proxy', path: '/data/app/~~vp==/com.free.vpn.proxy-bb==', uid: 10230,
      installerLines: ['installSource=InstallSource{installerPackageName=com.google.android.packageinstaller, initiatingPackageName=com.android.chrome, originatingPackageName=null, packageSource=3}'],
      requested: [P + 'INTERNET'], granted: [P + 'INTERNET'],
    }),
    // A malformed block from an odd OEM build: unterminated flags, a junk line, no User line.
    `  Package [com.oem.weird] (ffff):
    appId=10240
    codePath=/data/app/~~wd==/com.oem.weird-cc==
    flags=[ HAS_CODE ALLOW_BACKUP
    ???? garbage: [[[
    installerPackageName=com.android.vending
    requested permissions:
      android.permission.INTERNET
`,
    // Installed only in the work profile (user 10): an MDM-style tracker with accessibility there.
    pkgBlock({
      style: 'a14', pkg: 'com.mdm.agent.tracker', path: '/data/app/~~md==/com.mdm.agent.tracker-dd==', uid: 10250, installer: null,
      requested: [P + 'ACCESS_FINE_LOCATION', P + 'READ_CONTACTS', P + 'INTERNET'], granted: [P + 'INTERNET'],
      users: [{ id: 0, installed: false }, { id: 10, runtime: [P + 'ACCESS_FINE_LOCATION', P + 'READ_CONTACTS'], first: '2026-10-29 03:00:00' }],
    }),
    // Shows only on a TV launcher (LEANBACK_LAUNCHER): counts as having an icon.
    pkgBlock({ style: 'a14', pkg: 'com.tv.remote.helper', path: '/data/app/~~tv==/com.tv.remote.helper-ee==', uid: 10260, installer: 'com.android.vending', requested: [P + 'INTERNET'], granted: [P + 'INTERNET'] }),
  ];
  const hidden = [
    pkgBlock({ style: 'a14', pkg: 'com.google.android.gms', path: '/system/priv-app/PrebuiltGmsCore', uid: 10100, system: true, requested: [P + 'INTERNET'] }),
  ];
  const userLauncher = (lines) => `${lines.length} activities found:\n${lines.map((l, i) => `  Activity #${i}:\n    priority=0 preferredOrder=0 match=0x108000 specificIndex=-1 isDefault=false\n    ${l}`).join('\n')}\n`;
  write('work-pixel', {
    'devices -l': "adb server version (40) doesn't match this client (41); killing...\n* daemon started successfully\nList of devices attached\nemulator-5554          unauthorized transport_id:2\n37081FDJH000AB         device usb:2-1 product:shiba model:Pixel_8 device:shiba transport_id:4\n0123456789ABCDEF       no permissions (missing udev rules? user is in the plugdev group); see [http://developer.android.com/tools/device.html] usb:1-1 transport_id:5\n",
    'shell getprop ro.product.model': 'Pixel 8\n',
    'shell getprop ro.product.manufacturer': 'Google\n',
    'shell getprop ro.build.version.release': '14\n',
    'shell getprop ro.build.version.sdk': '34\n',
    'shell getprop ro.build.version.security_patch': '2026-09-05\n',
    'shell settings get global stay_on_while_plugged_in': 'null\n',
    'shell pm list users': 'Users:\n\tUserInfo{0:Owner:c13} running\n\tUserInfo{10:Work profile:1030} running\n',
    'shell settings get secure enabled_accessibility_services': 'null\n',
    'shell settings --user 10 get secure enabled_accessibility_services': 'com.mdm.agent.tracker/.TrackService\n',
    'shell settings --user 10 get secure enabled_notification_listeners': 'com.mdm.agent.tracker/.NotifTap\n',
    'shell settings get secure accessibility_button_targets': 'com.mdm.agent.tracker/com.mdm.agent.tracker.TrackService\n',
    [ROLE_CMD]: 'SMS=com.google.android.apps.messaging\nDIALER=com.google.android.dialer\nASSISTANT=com.google.android.googlequicksearchbox\nHOME=com.google.android.apps.nexuslauncher\n',
    [LAUNCHER]: userLauncher(['com.google.android.apps.nexuslauncher/.NexusLauncherActivity', 'com.spotify.music/.MainActivity', 'com.free.vpn.proxy/.Main']),
    [LEANBACK]: userLauncher(['com.tv.remote.helper/.TvMain']),
    'shell cmd package query-activities --brief --user 10 -a android.intent.action.MAIN -c android.intent.category.LAUNCHER': userLauncher(['com.google.android.apps.nexuslauncher/.NexusLauncherActivity']),
    'shell cmd package query-activities --brief --user 10 -a android.intent.action.MAIN -c android.intent.category.LEANBACK_LAUNCHER': 'No activities found\n',
    'shell ls /data/misc/user/0/cacerts-added 2>&1': 'ls: /data/misc/user/0/cacerts-added: No such file or directory\n',
    'shell dumpsys notification': `Current Notification Manager state:
  Notification listeners:
    Allowed user profiles: {0, 10}
    Enabled listeners:
      ComponentInfo{com.mdm.agent.tracker/com.mdm.agent.tracker.NotifTap}
    Live listeners (2):
      ComponentInfo{com.android.systemui/com.android.systemui.statusbar.notification.NotificationListener} (user 0): ManagedServiceInfo[component=ComponentInfo{com.android.systemui/com.android.systemui.statusbar.notification.NotificationListener}, userid=0]
      ComponentInfo{com.mdm.agent.tracker/com.mdm.agent.tracker.NotifTap} (user 10): ManagedServiceInfo[component=ComponentInfo{com.mdm.agent.tracker/com.mdm.agent.tracker.NotifTap}, userid=10]
    Snoozed notifications:
`,
    'shell dumpsys package packages': `Packages:\n${packages.join('\n')}\nHidden system packages:\n${hidden.join('\n')}`,
    'shell sha256sum *': `3333333333333333333333333333333333333333333333333333333333333333  /data/app/~~md==/com.mdm.agent.tracker-dd==/base.apk
`,
    'shell ps -A -o NAME*': 'NAME\ncom.mdm.agent.tracker\ncom.google.android.gms.persistent\n',
  });
}
