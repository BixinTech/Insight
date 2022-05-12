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

function printStackTrace() {
  const Thread = Java.use("java.lang.Thread");
  const thread = Thread.currentThread();
  log(thread.getStackTrace());
}

Java.perform(() => {
  const ActivityThread = Java.use("android.app.ActivityThread");
  const processName = ActivityThread.currentProcessName();
  log(processName);
  const dangerDirectories = ["/data/user/0/" + processName + "/lib-main/"];

  //#region java.io.RandomAccessFile
  const RandomAccessFile = Java.use("java.io.RandomAccessFile");
  RandomAccessFile.$init.overload(
    "java.io.File",
    "java.lang.String"
  ).implementation = function (file: string, mode) {
    dangerDirectories.forEach((dangerDirectory) => {
      if (file.toString().startsWith(dangerDirectory)) {
        send(`[java.io.RandomAccessFile $init] file: ${file}, mode: ${mode}`);
        printStackTrace();
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
        printStackTrace();
      }
    });
    this.$init(name, mode);
  };
  //#endregion

  //#region android.app.ActivityManager
  const ActivityManager = Java.use("android.app.ActivityManager");
  ActivityManager.getRunningAppProcesses.implementation = function () {
    send(`[android.app.ActivityManager getRunningAppProcesses]`);
    printStackTrace();
    return this.getRunningAppProcesses();
  };
  //#endregion

  //#region java.net.NetworkInterface
  const NetworkInterface = Java.use("java.net.NetworkInterface");
  NetworkInterface.getHardwareAddress.implementation = function () {
    send(`[java.net.NetworkInterface getHardwareAddress]`);
    printStackTrace();
    return this.getHardwareAddress();
  };
  //#endregion

  //#region java.io.FileOutputStream
  const FileOutputStream = Java.use("java.io.FileOutputStream");

  FileOutputStream.$init.overload("java.io.File").implementation = function (
    file
  ) {
    send(`[java.io.FileOutputStream $init] file: ${file}`);
    printStackTrace();
    this.$init(file);
  };

  FileOutputStream.$init.overload("java.io.FileDescriptor").implementation =
    function (fdObj) {
      send(`[java.io.FileOutputStream $init] fdObj: ${fdObj}`);
      printStackTrace();
      this.$init(fdObj);
    };

  FileOutputStream.$init.overload("java.lang.String").implementation =
    function (name) {
      send(`[java.io.FileOutputStream $init] name: ${name}`);
      printStackTrace();
      this.$init(name);
    };

  FileOutputStream.$init.overload("java.io.File", "boolean").implementation =
    function (file, append) {
      send(`[java.io.FileOutputStream $init] file: ${file}, append: ${append}`);
      printStackTrace();
      this.$init(file, append);
    };

  FileOutputStream.$init.overload(
    "java.io.FileDescriptor",
    "boolean"
  ).implementation = function (fdObj, append) {
    send(`[java.io.FileOutputStream $init] fdObj: ${fdObj}, append: ${append}`);
    printStackTrace();
    this.$init(fdObj, append);
  };

  FileOutputStream.$init.overload(
    "java.lang.String",
    "boolean"
  ).implementation = function (name, append) {
    send(`[java.io.FileOutputStream $init] name: ${name}, append: ${append}`);
    printStackTrace();
    this.$init(name, append);
  };

  //#endregion

  //#region android.provider.Settings$Secure
  const Secure = Java.use("android.provider.Settings$Secure");
  Secure.getStringForUser.overload(
    "android.content.ContentResolver",
    "java.lang.String",
    "int"
  ).implementation = function (
    contentResolver: any,
    name: string,
    userHandle: number
  ) {
    send(
      `[android.provider.Settings$Secure getStringForUser] contentResolver: ${contentResolver}, name: ${name}, userHandle: ${userHandle}`
    );
    printStackTrace();
    return this.getStringForUser(contentResolver, name, userHandle);
  };
  //#endregion

  //#region android.os.SystemProperties
  const SystemProperties = Java.use("android.os.SystemProperties");
  SystemProperties.get.overload("java.lang.String").implementation = function (
    property: string
  ) {
    send(`[android.os.SystemProperties get] property: ${property}`);
    printStackTrace();
    return this.get(property);
  };
  //#endregion

  //#region android.app.ContextImpl
  const ContextImpl = Java.use("android.app.ContextImpl");
  ContextImpl.sendBroadcast.overload("android.content.Intent").implementation =
    function (intent: any) {
      send(`[android.app.ContextImpl sendBroadcast] intent: ${intent}`);
      printStackTrace();
      this.sendBroadcast(intent);
    };
  //#endregion

  //#region java.io.File
  const File = Java.use("java.io.File");
  File.delete.implementation = function () {
    send(`[java.io.File delete]`);
    printStackTrace();
    return this.delete();
  };
  //#endregion

  //#region java.io.FileInputStream
  const FileInputStream = Java.use("java.io.FileInputStream");
  FileInputStream.$init.overload("java.io.File").implementation = function (
    file
  ) {
    send(`[java.io.FileInputStream $init] file: ${file}`);
    printStackTrace();
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
    printStackTrace();
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
