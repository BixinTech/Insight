import { log } from "./logger";

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

Java.perform(() => {
  const ActivityThread = Java.use("android.app.ActivityThread");
  const processName = ActivityThread.currentProcessName();
  log(processName);

  //#region java.io.RandomAccessFile
  const dangerDirectories = ["/data/user/0/" + processName + "/lib-main/"];

  const RandomAccessFile = Java.use("java.io.RandomAccessFile");
  RandomAccessFile.$init.overload(
    "java.io.File",
    "java.lang.String"
  ).implementation = function (file: string, mode) {
    dangerDirectories.forEach((dangerDirectory) => {
      if (file.toString().startsWith(dangerDirectory)) {
        send(`[java.io.RandomAccessFile $init] file: ${file}, mode: ${mode}`);
        printStackTrace(getStackTrace());
      }
    });
    this.$init(file, mode);
  };
  RandomAccessFile.$init.overload(
    "java.lang.String",
    "java.lang.String"
  ).implementation = function (name: string, mode) {
    dangerDirectories.forEach((dangerDirectory) => {
      if (name.startsWith(dangerDirectory)) {
        send(`[java.io.RandomAccessFile $init] name: ${name}, mode: ${mode}`);
        printStackTrace(getStackTrace());
      }
    });
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

  const targets = ["nim_sdk.log"];

  FileOutputStream.$init.overload("java.io.File").implementation = function (
    file
  ) {
    send(`[java.io.FileOutputStream $init] file: ${file}`);
    targets.forEach((target) => {
      const absolutePath = file.getAbsolutePath().toString() as string;
      if (absolutePath.includes(target)) {
        printStackTrace(getStackTrace());
      }
    });

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
      targets.forEach((target) => {
        if (absolutePath.includes(target)) {
          printStackTrace(getStackTrace());
        }
      });
      this.$init(fdObj);
    };

  FileOutputStream.$init.overload("java.lang.String").implementation =
    function (name) {
      send(`[java.io.FileOutputStream $init] name: ${name}`);
      getStackTrace();
      this.$init(name);
    };

  FileOutputStream.$init.overload("java.io.File", "boolean").implementation =
    function (file, append) {
      send(`[java.io.FileOutputStream $init] file: ${file}, append: ${append}`);
      getStackTrace();
      this.$init(file, append);
    };

  FileOutputStream.$init.overload(
    "java.io.FileDescriptor",
    "boolean"
  ).implementation = function (fdObj, append) {
    send(`[java.io.FileOutputStream $init] fdObj: ${fdObj}, append: ${append}`);
    printStackTrace(getStackTrace());
    this.$init(fdObj, append);
  };

  FileOutputStream.$init.overload(
    "java.lang.String",
    "boolean"
  ).implementation = function (name, append) {
    send(`[java.io.FileOutputStream $init] name: ${name}, append: ${append}`);
    getStackTrace();
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
    getStackTrace();
    return this.getStringForUser(contentResolver, name, userHandle);
  };
  //#endregion

  //#region android.os.SystemProperties
  const SystemProperties = Java.use("android.os.SystemProperties");
  SystemProperties.get.overload("java.lang.String").implementation = function (
    key: string
  ) {
    send(`[android.os.SystemProperties get] key: ${key}`);
    getStackTrace();
    return this.get(key);
  };
  SystemProperties.get.overload(
    "java.lang.String",
    "java.lang.String"
  ).implementation = function (key: string, def: string) {
    send(`[android.os.SystemProperties get] key: ${key}, def: ${def}`);
    getStackTrace();
    return this.get(key, def);
  };
  //#endregion

  //#region android.app.ContextImpl
  const ContextImpl = Java.use("android.app.ContextImpl");
  ContextImpl.sendBroadcast.overload("android.content.Intent").implementation =
    function (intent: any) {
      send(`[android.app.ContextImpl sendBroadcast] intent: ${intent}`);
      getStackTrace();
      this.sendBroadcast(intent);
    };
  //#endregion

  //#region java.io.File
  const File = Java.use("java.io.File");
  File.delete.implementation = function () {
    send(`[java.io.File delete]`);
    getStackTrace();
    return this.delete();
  };
  //#endregion

  //#region java.io.FileInputStream
  const FileInputStream = Java.use("java.io.FileInputStream");
  FileInputStream.$init.overload("java.io.File").implementation = function (
    file
  ) {
    send(`[java.io.FileInputStream $init] file: ${file}`);
    getStackTrace();
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
    getStackTrace();
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
});
