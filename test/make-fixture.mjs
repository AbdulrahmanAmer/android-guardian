// Builds test/fixtures/infected/commands.json: a synthetic phone with one known stalkerware app
// (com.systemservice, on the Echap list as TheTruthSpy), one hidden home-made RAT, one normal
// Play-installed app and system apps. Formats follow real `dumpsys` output from Android 13.
import { writeFileSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const dir = join(dirname(fileURLToPath(import.meta.url)), 'fixtures', 'infected');
mkdirSync(dir, { recursive: true });

function pkgBlock({ pkg, path, uid, installer, system = false, requested = [], granted = [], runtime = [], first = '2023-01-10 09:00:00', version = '1.0' }) {
  const flags = system ? 'SYSTEM HAS_CODE ALLOW_CLEAR_USER_DATA' : 'HAS_CODE ALLOW_BACKUP';
  return `  Package [${pkg}] (a1b2c3):
    appId=${uid}
    pkg=Package{1234 ${pkg}}
    codePath=${path}
    resourcePath=${path}
    primaryCpuAbi=null
    versionCode=1 minSdk=23 targetSdk=33
    versionName=${version}
    flags=[ ${flags} ]
    privateFlags=[ PRIVATE_FLAG_ALLOW_AUDIO_PLAYBACK_CAPTURE ]
    dataDir=/data/user/0/${pkg}
    timeStamp=2023-01-10 09:00:00
    lastUpdateTime=2023-01-10 09:00:00
    firstInstallTime=${first}
    installerPackageName=${installer ?? 'null'}
    signatures=PackageSignatures{abc version:3, signatures:[xyz], past signatures:[]}
    installPermissionsFixed=true
    pkgFlags=[ ${flags} ]
    requested permissions:
${requested.map((p) => `      ${p}`).join('\n')}
    install permissions:
${granted.map((p) => `      ${p}: granted=true`).join('\n')}
    User 0: ceDataInode=0 installed=true hidden=false suspended=false distractionFlags=0 stopped=false notLaunched=false enabled=0 instant=false virtual=false
      lastDisabledCaller: null
      gids=[3003]
      runtime permissions:
${runtime.map((p) => `        ${p}: granted=true, flags=[ USER_SET|USER_SENSITIVE_WHEN_GRANTED ]`).join('\n')}
`;
}

const P = 'android.permission.';
const packages = [
  pkgBlock({ pkg: 'com.android.settings', path: '/system_ext/priv-app/Settings', uid: 1000, system: true, requested: [P + 'WRITE_SECURE_SETTINGS'], granted: [P + 'WRITE_SECURE_SETTINGS'] }),
  pkgBlock({ pkg: 'com.android.vending', path: '/product/priv-app/Phonesky', uid: 10050, system: true, requested: [P + 'INTERNET'], granted: [P + 'INTERNET'] }),
  pkgBlock({ pkg: 'com.google.android.marvin.talkback', path: '/product/app/talkback', uid: 10060, system: true, requested: [P + 'BIND_ACCESSIBILITY_SERVICE'] }),
  pkgBlock({
    pkg: 'com.whatsapp', path: '/data/app/~~abc==/com.whatsapp-xyz==', uid: 10200, installer: 'com.android.vending',
    requested: [P + 'RECORD_AUDIO', P + 'CAMERA', P + 'READ_CONTACTS', P + 'ACCESS_FINE_LOCATION', P + 'READ_EXTERNAL_STORAGE', P + 'INTERNET'],
    granted: [P + 'INTERNET'], runtime: [P + 'RECORD_AUDIO', P + 'CAMERA', P + 'READ_CONTACTS'], first: '2022-05-01 12:00:00', version: '2.24.1',
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
];

const commands = {
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
  'shell date +%s': '1793400000\n',
  'shell settings get secure enabled_accessibility_services': 'com.systemservice/com.systemservice.AccService:com.google.android.marvin.talkback/com.google.android.marvin.talkback.TalkBackService\n',
  'shell settings get secure enabled_notification_listeners': 'com.wifi.update.service/.NotifService\n',
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
  'shell cmd package query-activities --brief -a android.intent.action.MAIN -c android.intent.category.LAUNCHER': `1 activities found:
  com.android.settings/.Settings
  com.whatsapp/.Main
  org.supertuxkart.stk/.SuperTuxKartActivity
  com.android.vending/.AssetBrowserActivity
`,
  'shell appops query-op GET_USAGE_STATS allow*': 'com.systemservice\n',
  'shell dumpsys package packages': `Packages:\n${packages.join('\n')}`,
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
};

writeFileSync(join(dir, 'commands.json'), JSON.stringify(commands, null, 1));
console.log(`fixture written: ${join(dir, 'commands.json')} (${Object.keys(commands).length} commands)`);
