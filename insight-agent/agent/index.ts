import { log } from "./logger";

const API_BASE_URL = "http://insight-app.yupaopao.com:9080";

const header = Memory.alloc(16);
header
  .writeU32(0xdeadbeef)
  .add(4)
  .writeU32(0xd00ff00d)
  .add(4)
  .writeU64(uint64("0x1122334455667788"));
log(hexdump(header.readByteArray(16) as ArrayBuffer, { ansi: true }));

Process.getModuleByName("libfrida-gadget.so")
  .enumerateExports()
  .slice(0, 16)
  .forEach((exp, index) => {
    log(`export ${index}: ${exp.name}`);
  });

// Interceptor.attach(Module.getExportByName(null, "open"), {
//   onEnter(args) {
//     const path = args[0].readUtf8String();
//     log(`open() path="${path}"`);
//   },
// });

function getStackTrace() {
  const Thread = Java.use("java.lang.Thread");
  const thread = Thread.currentThread();
  const stackTraceString = thread.getStackTrace().toString();
  const stackTraces = stackTraceString.split(",");
  return stackTraces;
}

function printStackTrace(stackTraces: Array<string>) {
  stackTraces.forEach((stackTrace: any) => {
    log(stackTrace + ",");
  });
}

function formatStackTrace(stackTraces: Array<string>) {
  let result = "";

  for (let index = 0; index < stackTraces.length; index++) {
    result += stackTraces[index] + ",";
  }
  return result;
}

Java.perform(() => {
  const ActivityThread = Java.use("android.app.ActivityThread");
  const processName = ActivityThread.currentProcessName();
  log(processName);

  const InsightApi = Java.use("cn.bixin.InsightApi");

  //#region java.io.RandomAccessFile
  const RandomAccessFile = Java.use("java.io.RandomAccessFile");
  RandomAccessFile.$init.overload(
    "java.io.File",
    "java.lang.String"
  ).implementation = function (file: string, mode) {
    send(`[java.io.RandomAccessFile $init] file: ${file}, mode: ${mode}`);
    printStackTrace(getStackTrace());
    InsightApi.getInstance().flush(
      API_BASE_URL + "/flush",
      `[java.io.RandomAccessFile $init] file: ${file}, mode: ${mode}`,
      formatStackTrace(getStackTrace())
    );
    this.$init(file, mode);
  };
  RandomAccessFile.$init.overload(
    "java.lang.String",
    "java.lang.String"
  ).implementation = function (name: string, mode) {
    send(`[java.io.RandomAccessFile $init] name: ${name}, mode: ${mode}`);
    printStackTrace(getStackTrace());
    this.$init(name, mode);
  };
  //#endregion

  //#region android.app.ActivityManager
  const ActivityManager = Java.use("android.app.ActivityManager");
  ActivityManager.getRunningAppProcesses.implementation = function () {
    send(`[android.app.ActivityManager getRunningAppProcesses]`);
    printStackTrace(getStackTrace());
    return this.getRunningAppProcesses();
  };
  //#endregion

  //#region java.net.NetworkInterface
  const NetworkInterface = Java.use("java.net.NetworkInterface");
  NetworkInterface.getHardwareAddress.implementation = function () {
    send(`[java.net.NetworkInterface getHardwareAddress]`);
    printStackTrace(getStackTrace());
    return this.getHardwareAddress();
  };
  //#endregion

  //#region java.io.FileOutputStream
  const FileOutputStream = Java.use("java.io.FileOutputStream");

  FileOutputStream.$init.overload("java.io.File").implementation = function (
    file
  ) {
    send(`[java.io.FileOutputStream $init] file: ${file}`);
    const absolutePath = file.getAbsolutePath().toString() as string;
    printStackTrace(getStackTrace());

    this.$init(file);
  };

  FileOutputStream.$init.overload("java.io.FileDescriptor").implementation =
    function (fdObj) {
      send(`[java.io.FileOutputStream $init] fdObj: ${fdObj}`);
      const fdId = fdObj.getInt$();
      const Paths = Java.use("java.nio.file.Paths");
      const path = Paths.get(`/proc/self/fd/${fdId}`, []);
      const Files = Java.use("java.nio.file.Files");
      const absolutePath = Files.readSymbolicLink(path).toString();
      printStackTrace(getStackTrace());
      this.$init(fdObj);
    };

  FileOutputStream.$init.overload("java.lang.String").implementation =
    function (name) {
      send(`[java.io.FileOutputStream $init] name: ${name}`);
      printStackTrace(getStackTrace());
      this.$init(name);
    };

  FileOutputStream.$init.overload("java.io.File", "boolean").implementation =
    function (file, append) {
      send(`[java.io.FileOutputStream $init] file: ${file}, append: ${append}`);
      printStackTrace(getStackTrace());
      this.$init(file, append);
    };

  FileOutputStream.$init.overload(
    "java.io.FileDescriptor",
    "boolean"
  ).implementation = function (fdObj, append) {
    send(`[java.io.FileOutputStream $init] fdObj: ${fdObj}, append: ${append}`);
    const fdId = fdObj.getInt$();
    const Paths = Java.use("java.nio.file.Paths");
    const path = Paths.get(`/proc/self/fd/${fdId}`, []);
    const Files = Java.use("java.nio.file.Files");
    const absolutePath = Files.readSymbolicLink(path).toString();
    printStackTrace(getStackTrace());
    this.$init(fdObj, append);
  };

  FileOutputStream.$init.overload(
    "java.lang.String",
    "boolean"
  ).implementation = function (name, append) {
    send(`[java.io.FileOutputStream $init] name: ${name}, append: ${append}`);
    printStackTrace(getStackTrace());
    this.$init(name, append);
  };

  //#endregion

  //#region android.provider.Settings$Secure
  const Secure = Java.use("android.provider.Settings$Secure");
  Secure.getStringForUser.implementation = function (
    contentResolver: any,
    name: string,
    userHandle: number
  ) {
    send(
      `[android.provider.Settings$Secure getStringForUser] contentResolver: ${contentResolver}, name: ${name}, userHandle: ${userHandle}`
    );
    printStackTrace(getStackTrace());
    return this.getStringForUser(contentResolver, name, userHandle);
  };
  //#endregion

  //#region android.os.SystemProperties
  const SystemProperties = Java.use("android.os.SystemProperties");
  SystemProperties.get.overload("java.lang.String").implementation = function (
    key: string
  ) {
    send(`[android.os.SystemProperties get] key: ${key}`);
    printStackTrace(getStackTrace());
    return this.get(key);
  };
  SystemProperties.get.overload(
    "java.lang.String",
    "java.lang.String"
  ).implementation = function (key: string, def: string) {
    send(`[android.os.SystemProperties get] key: ${key}, def: ${def}`);
    printStackTrace(getStackTrace());
    return this.get(key, def);
  };
  //#endregion

  //#region android.app.ContextImpl
  const ContextImpl = Java.use("android.app.ContextImpl");
  ContextImpl.sendBroadcast.overload("android.content.Intent").implementation =
    function (intent: any) {
      send(`[android.app.ContextImpl sendBroadcast] intent: ${intent}`);
      printStackTrace(getStackTrace());
      this.sendBroadcast(intent);
    };
  //#endregion

  //#region java.io.File
  const File = Java.use("java.io.File");
  File.delete.implementation = function () {
    send(`[java.io.File delete]`);
    printStackTrace(getStackTrace());
    return this.delete();
  };
  //#endregion

  //#region java.io.FileInputStream
  const FileInputStream = Java.use("java.io.FileInputStream");
  FileInputStream.$init.overload("java.io.File").implementation = function (
    file
  ) {
    send(`[java.io.FileInputStream $init] file: ${file}`);
    printStackTrace(getStackTrace());
    this.$init(file);
  };
  //#endregion

  //#region android.app.AlarmManager
  const AlarmManager = Java.use("android.app.AlarmManager");
  AlarmManager.setImpl.implementation = function (
    type: number,
    triggerAtMillis: number,
    windowMillis: number,
    intervalMillis: number,
    flags: number,
    operation: any,
    listener: any,
    listenerTag: string,
    targetHandler: any,
    workSource: any,
    alarmClock: any
  ) {
    send(
      `[android.app.AlarmManager $setImpl] type: ${type}, triggerAtMillis: ${triggerAtMillis}`
    );
    printStackTrace(getStackTrace());
    this.setImpl(
      type,
      triggerAtMillis,
      windowMillis,
      intervalMillis,
      flags,
      operation,
      listener,
      listenerTag,
      targetHandler,
      workSource,
      alarmClock
    );
  };
  //#endregion

  //#region android.content.Context
  const Context = Java.use("android.content.Context");
  Context.getSystemService.overload("java.lang.String").implementation =
    function (name: any) {
      send(`[android.content.Context getSystemService] name: ${name}`);
      printStackTrace(getStackTrace());
      return this.getSystemService(name);
    };

  Context.getSystemService.overload("java.lang.Class").implementation =
    function (className: any) {
      send(
        `[android.content.Context getSystemService] className: ${className}`
      );
      printStackTrace(getStackTrace());
      return this.getSystemService(className);
    };
  //#endregion

  //#region android.net.wifi.WifiInfo
  const WifiInfo = Java.use("android.net.wifi.WifiInfo");
  WifiInfo.getMacAddress.implementation = function () {
    send(`[android.net.wifi.WifiInfo getMacAddress]`);
    printStackTrace(getStackTrace());
    return this.getMacAddress();
  };

  WifiInfo.getSSID.implementation = function () {
    send(`[android.net.wifi.WifiInfo getSSID]`);
    printStackTrace(getStackTrace());
    return this.getSSID();
  };
  //#endregion

  //#region android.net.NetworkInfo
  const NetworkInfo = Java.use("android.net.NetworkInfo");
  NetworkInfo.getExtraInfo.implementation = function () {
    send(`[android.net.NetworkInfo getExtraInfo]`);
    printStackTrace(getStackTrace());
    return this.getExtraInfo();
  };
  //#endregion

  //#region java.lang.Runtime
  const Runtime = Java.use("java.lang.Runtime");
  Runtime.exec.overload("java.lang.String").implementation = function (
    command: string
  ) {
    send(`[java.lang.Runtime exec] command: ${command}`);
    printStackTrace(getStackTrace());
    return this.exec(command);
  };
  //#endregion

  //#region android.location.LocationManager
  const LocationManager = Java.use("android.location.LocationManager");
  LocationManager.$init.implementation = function () {
    send(`[android.location.LocationManager $init]`);
    printStackTrace(getStackTrace());
    this.$init();
  };
  LocationManager.requestLocationUpdates.overload(
    "java.lang.String",
    "long",
    "float",
    "android.location.LocationListener",
    "android.os.Looper"
  ).implementation = function (
    provider: any,
    minTimeMs: any,
    minDistanceM: any,
    listener: any,
    looper: any
  ) {
    send(
      `[android.location.LocationManager requestLocationUpdates] provider: ${provider}`
    );
    printStackTrace(getStackTrace());
    this.requestLocationUpdates(
      provider,
      minTimeMs,
      minDistanceM,
      listener,
      looper
    );
  };

  LocationManager.getLastKnownLocation.implementation = function (
    provider: any
  ) {
    send(
      `[android.location.LocationManager getLastKnownLocation] provider: ${provider}`
    );
    printStackTrace(getStackTrace());
    return this.getLastKnownLocation(provider);
  };
  //#endregion
});
