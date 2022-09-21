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

function send(content: string) {
  console.log("message::" + content);
}

Java.perform(() => {
  const ActivityThread = Java.use("android.app.ActivityThread");
  const processName = ActivityThread.currentProcessName();
  log(processName);

  const safeDirectories = [
    "/storage/emulated/0/Android/data/" + processName + "/",
    "/data/user/0/" + processName + "/",
  ];

  const InsightApi = Java.use("cn.bixin.InsightApi");

  //#region java.io.RandomAccessFile
  const RandomAccessFile = Java.use("java.io.RandomAccessFile");
  RandomAccessFile.$init.overload(
    "java.io.File",
    "java.lang.String"
  ).implementation = function (file: string, mode) {
    let skip = false;
    safeDirectories.forEach((safeDirectory) => {
      if (file.toString().includes(safeDirectory)) {
        skip = true;
      }
    });
    if (!skip) {
      const signature = `[java.io.RandomAccessFile $init] file: ${file}, mode: ${mode}`;
      send(signature);
      printStackTrace(getStackTrace());

      InsightApi.getInstance().flush(
        API_BASE_URL + "/flush",
        signature,
        formatStackTrace(getStackTrace())
      );
    }

    this.$init(file, mode);
  };
  RandomAccessFile.$init.overload(
    "java.lang.String",
    "java.lang.String"
  ).implementation = function (name: string, mode) {
    let skip = false;
    safeDirectories.forEach((safeDirectory) => {
      if (name.includes(safeDirectory)) {
        skip = true;
      }
    });
    if (!skip) {
      const signature = `[java.io.RandomAccessFile $init] name: ${name}, mode: ${mode}`;
      send(signature);
      printStackTrace(getStackTrace());

      InsightApi.getInstance().flush(
        API_BASE_URL + "/flush",
        signature,
        formatStackTrace(getStackTrace())
      );
    }
    this.$init(name, mode);
  };
  //#endregion

  //#region android.app.ActivityManager
  const ActivityManager = Java.use("android.app.ActivityManager");
  ActivityManager.getRunningAppProcesses.implementation = function () {
    const signature = `[android.app.ActivityManager getRunningAppProcesses]`;
    send(signature);
    printStackTrace(getStackTrace());
    InsightApi.getInstance().flush(
      API_BASE_URL + "/flush",
      signature,
      formatStackTrace(getStackTrace())
    );
    return this.getRunningAppProcesses();
  };
  //#endregion

  //#region java.net.NetworkInterface
  const NetworkInterface = Java.use("java.net.NetworkInterface");
  NetworkInterface.getHardwareAddress.implementation = function () {
    const signature = `[java.net.NetworkInterface getHardwareAddress]`;
    send(signature);
    printStackTrace(getStackTrace());
    InsightApi.getInstance().flush(
      API_BASE_URL + "/flush",
      signature,
      formatStackTrace(getStackTrace())
    );
    return this.getHardwareAddress();
  };
  //#endregion

  //#region java.io.FileOutputStream
  const FileOutputStream = Java.use("java.io.FileOutputStream");

  FileOutputStream.$init.overload("java.io.File").implementation = function (
    file
  ) {
    const absolutePath = file.getAbsolutePath().toString() as string;
    let skip = false;
    safeDirectories.forEach((safeDirectory) => {
      if (absolutePath.includes(safeDirectory)) {
        skip = true;
      }
    });
    if (!skip) {
      const signature = `[java.io.FileOutputStream $init] file: ${file}`;
      send(signature);
      printStackTrace(getStackTrace());
      InsightApi.getInstance().flush(
        API_BASE_URL + "/flush",
        signature,
        formatStackTrace(getStackTrace())
      );
    }

    this.$init(file);
  };

  // FileOutputStream.$init.overload("java.io.FileDescriptor").implementation =
  //   function (fdObj) {
  //     const fdId = fdObj.getInt$();
  //     const Paths = Java.use("java.nio.file.Paths");
  //     const path = Paths.get(`/proc/self/fd/${fdId}`, []);
  //     const Files = Java.use("java.nio.file.Files");
  //     const absolutePath = Files.readSymbolicLink(path).toString();
  //     let skip = false;
  //     safeDirectories.forEach((safeDirectory) => {
  //       if (absolutePath.includes(safeDirectory)) {
  //         skip = true;
  //       }
  //     });
  //     if (!skip) {
  //       const signature = `[java.io.FileOutputStream $init] fdObj: ${fdObj}`;
  //       send(signature);
  //       printStackTrace(getStackTrace());
  //       InsightApi.getInstance().flush(
  //         API_BASE_URL + "/flush",
  //         signature,
  //         formatStackTrace(getStackTrace())
  //       );
  //     }
  //     this.$init(fdObj);
  //   };

  FileOutputStream.$init.overload("java.lang.String").implementation =
    function (name) {
      let skip = false;
      safeDirectories.forEach((safeDirectory) => {
        if (name.includes(safeDirectory)) {
          skip = true;
        }
      });
      if (!skip) {
        const signature = `[java.io.FileOutputStream $init] name: ${name}`;
        send(signature);
        printStackTrace(getStackTrace());
        InsightApi.getInstance().flush(
          API_BASE_URL + "/flush",
          signature,
          formatStackTrace(getStackTrace())
        );
      }
      this.$init(name);
    };

  FileOutputStream.$init.overload("java.io.File", "boolean").implementation =
    function (file, append) {
      let skip = false;
      safeDirectories.forEach((safeDirectory) => {
        if (file.getAbsolutePath().includes(safeDirectory)) {
          skip = true;
        }
      });
      if (!skip) {
        const signature = `[java.io.FileOutputStream $init] file: ${file}, append: ${append}`;
        send(signature);
        printStackTrace(getStackTrace());
        InsightApi.getInstance().flush(
          API_BASE_URL + "/flush",
          signature,
          formatStackTrace(getStackTrace())
        );
      }
      this.$init(file, append);
    };

  // FileOutputStream.$init.overload(
  //   "java.io.FileDescriptor",
  //   "boolean"
  // ).implementation = function (fdObj, append) {
  //   const fdId = fdObj.getInt$();
  //   const Paths = Java.use("java.nio.file.Paths");
  //   const path = Paths.get(`/proc/self/fd/${fdId}`, []);
  //   const Files = Java.use("java.nio.file.Files");
  //   const absolutePath = Files.readSymbolicLink(path).toString();
  //   let skip = false;
  //   safeDirectories.forEach((safeDirectory) => {
  //     if (absolutePath.includes(safeDirectory)) {
  //       skip = true;
  //     }
  //   });
  //   if (!skip) {
  //     const signature = `[java.io.FileOutputStream $init] fdObj: ${fdObj}, append: ${append}`;
  //     send(signature);
  //     printStackTrace(getStackTrace());
  //     InsightApi.getInstance().flush(
  //       API_BASE_URL + "/flush",
  //       signature,
  //       formatStackTrace(getStackTrace())
  //     );
  //   }
  //   this.$init(fdObj, append);
  // };

  FileOutputStream.$init.overload(
    "java.lang.String",
    "boolean"
  ).implementation = function (name, append) {
    let skip = false;
    safeDirectories.forEach((safeDirectory) => {
      if (name.includes(safeDirectory)) {
        skip = true;
      }
    });
    if (!skip) {
      const signature = `[java.io.FileOutputStream $init] name: ${name}, append: ${append}`;
      send(signature);
      printStackTrace(getStackTrace());
      InsightApi.getInstance().flush(
        API_BASE_URL + "/flush",
        signature,
        formatStackTrace(getStackTrace())
      );
    }
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
    const signature = `[android.provider.Settings$Secure getStringForUser] contentResolver: ${contentResolver}, name: ${name}, userHandle: ${userHandle}`;
    send(signature);
    printStackTrace(getStackTrace());
    InsightApi.getInstance().flush(
      API_BASE_URL + "/flush",
      signature,
      formatStackTrace(getStackTrace())
    );
    return this.getStringForUser(contentResolver, name, userHandle);
  };
  //#endregion

  //#region android.os.SystemProperties
  const SystemProperties = Java.use("android.os.SystemProperties");
  SystemProperties.get.overload("java.lang.String").implementation = function (
    key: string
  ) {
    const signature = `[android.os.SystemProperties get] key: ${key}`;
    send(signature);
    printStackTrace(getStackTrace());
    InsightApi.getInstance().flush(
      API_BASE_URL + "/flush",
      signature,
      formatStackTrace(getStackTrace())
    );
    return this.get(key);
  };
  SystemProperties.get.overload(
    "java.lang.String",
    "java.lang.String"
  ).implementation = function (key: string, def: string) {
    const signature = `[android.os.SystemProperties get] key: ${key}, def: ${def}`;

    send(signature);
    printStackTrace(getStackTrace());
    InsightApi.getInstance().flush(
      API_BASE_URL + "/flush",
      signature,
      formatStackTrace(getStackTrace())
    );
    return this.get(key, def);
  };
  //#endregion

  //#region android.app.ContextImpl
  const ContextImpl = Java.use("android.app.ContextImpl");
  ContextImpl.sendBroadcast.overload("android.content.Intent").implementation =
    function (intent: any) {
      const signature = `[android.app.ContextImpl sendBroadcast] intent: ${intent}`;
      const description = `发送系统广播:参数为intent`;
      send(description);
      send(signature);
      printStackTrace(getStackTrace());
      InsightApi.getInstance().flush(
        API_BASE_URL + "/flush",
        description,
        formatStackTrace(getStackTrace())
      );
      InsightApi.getInstance().flush(
        API_BASE_URL + "/flush",
        signature,
        formatStackTrace(getStackTrace())
      );
      this.sendBroadcast(intent);
    };

  
    ContextImpl.sendBroadcast.overload("android.content.Intent","java.lang.String").implementation =
    function (intent: any,receiverPermission:any) {
      const signature = `[android.app.ContextImpl sendBroadcast] intent: ${intent}`;
      const description = `发送系统广播：参数为intent，receiverPermission`;
      send(description);
      send(signature);
      printStackTrace(getStackTrace());
      InsightApi.getInstance().flush(
        API_BASE_URL + "/flush",
        description,
        formatStackTrace(getStackTrace())
      );
      InsightApi.getInstance().flush(
        API_BASE_URL + "/flush",
        signature,
        formatStackTrace(getStackTrace())
      );
      this.sendBroadcast(intent);
    };

    ContextImpl.sendBroadcast.overload("android.content.Intent","java.lang.String","android.os.Bundle").implementation =
    function (intent: any,receiverPermission: any,options: any) {
      const signature = `[android.app.ContextImpl sendBroadcast] intent: ${intent}`;
      const description = `发送系统广播：参数为intent，receiverPermission,options`;
      send(description);
      send(signature);
      printStackTrace(getStackTrace());
      InsightApi.getInstance().flush(
        API_BASE_URL + "/flush",
        description,
        formatStackTrace(getStackTrace())
      );
      InsightApi.getInstance().flush(
        API_BASE_URL + "/flush",
        signature,
        formatStackTrace(getStackTrace())
      );
      this.sendBroadcast(intent);
    };
    
    ContextImpl.sendBroadcast.overload("android.content.Intent","java.lang.String","int").implementation =
    function (intent: any,receiverPermission:any,appOp:any) {
      const signature = `[android.app.ContextImpl sendBroadcast] intent: ${intent}`;
      const description = `发送系统广播:参数为intent，receiverPermission,appOp`;
      send(description);
      send(signature);
      printStackTrace(getStackTrace());
      InsightApi.getInstance().flush(
        API_BASE_URL + "/flush",
        description,
        formatStackTrace(getStackTrace())
      );
      InsightApi.getInstance().flush(
        API_BASE_URL + "/flush",
        signature,
        formatStackTrace(getStackTrace())
      );
      this.sendBroadcast(intent);
    };
  //#endregion

  //#region java.io.File
  const File = Java.use("java.io.File");
  File.delete.implementation = function () {
    const signature = `[java.io.File delete]`;
    send(signature);
    printStackTrace(getStackTrace());
    InsightApi.getInstance().flush(
      API_BASE_URL + "/flush",
      signature,
      formatStackTrace(getStackTrace())
    );
    return this.delete();
  };
  //#endregion

  //#region java.io.FileInputStream
  const FileInputStream = Java.use("java.io.FileInputStream");
  FileInputStream.$init.overload("java.io.File").implementation = function (
    file
  ) {
    let skip = false;
    safeDirectories.forEach((safeDirectory) => {
      if (file.getAbsolutePath().includes(safeDirectory)) {
        skip = true;
      }
    });
    if (!skip) {
      const signature = `[java.io.FileInputStream $init] file: ${file}`;
      send(signature);
      printStackTrace(getStackTrace());
      InsightApi.getInstance().flush(
        API_BASE_URL + "/flush",
        signature,
        formatStackTrace(getStackTrace())
      );
    }
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
    const signature = `[android.app.AlarmManager setImpl] type: ${type}, triggerAtMillis: ${triggerAtMillis}`;
    send(signature);
    printStackTrace(getStackTrace());
    InsightApi.getInstance().flush(
      API_BASE_URL + "/flush",
      signature,
      formatStackTrace(getStackTrace())
    );
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
      const signature = `[android.content.Context getSystemService] name: ${name}`;
      send(signature);
      printStackTrace(getStackTrace());
      InsightApi.getInstance().flush(
        API_BASE_URL + "/flush",
        signature,
        formatStackTrace(getStackTrace())
      );
      return this.getSystemService(name);
    };

  Context.getSystemService.overload("java.lang.Class").implementation =
    function (className: any) {
      const signature = `[android.content.Context getSystemService] className: ${className}`;
      send(signature);
      printStackTrace(getStackTrace());
      InsightApi.getInstance().flush(
        API_BASE_URL + "/flush",
        signature,
        formatStackTrace(getStackTrace())
      );
      return this.getSystemService(className);
    };
  //#endregion

  //#region android.net.wifi.WifiInfo
  const WifiInfo = Java.use("android.net.wifi.WifiInfo");
  WifiInfo.getMacAddress.implementation = function () {
    const signature = `[android.net.wifi.WifiInfo getMacAddress]`;
    send(signature);
    printStackTrace(getStackTrace());
    InsightApi.getInstance().flush(
      API_BASE_URL + "/flush",
      signature,
      formatStackTrace(getStackTrace())
    );
    return this.getMacAddress();
  };

  WifiInfo.getSSID.implementation = function () {
    const signature = `[android.net.wifi.WifiInfo getSSID]`;
    send(signature);
    printStackTrace(getStackTrace());
    InsightApi.getInstance().flush(
      API_BASE_URL + "/flush",
      signature,
      formatStackTrace(getStackTrace())
    );
    return this.getSSID();
  };
  //#endregion

  //#region android.net.NetworkInfo
  const NetworkInfo = Java.use("android.net.NetworkInfo");
  NetworkInfo.getExtraInfo.implementation = function () {
    const signature = `[android.net.NetworkInfo getExtraInfo]`;
    send(signature);
    printStackTrace(getStackTrace());
    InsightApi.getInstance().flush(
      API_BASE_URL + "/flush",
      signature,
      formatStackTrace(getStackTrace())
    );
    return this.getExtraInfo();
  };
  //#endregion

  //#region java.lang.Runtime
  const Runtime = Java.use("java.lang.Runtime");
  Runtime.exec.overload("java.lang.String").implementation = function (
    command: string
  ) {
    const signature = `[java.lang.Runtime exec] command: ${command}`;
    send(signature);
    printStackTrace(getStackTrace());
    InsightApi.getInstance().flush(
      API_BASE_URL + "/flush",
      signature,
      formatStackTrace(getStackTrace())
    );
    return this.exec(command);
  };
  //#endregion

  //#region android.location.LocationManager
  const LocationManager = Java.use("android.location.LocationManager");
  LocationManager.$init.implementation = function () {
    const signature = `[android.location.LocationManager $init]`;
    send(signature);
    printStackTrace(getStackTrace());
    InsightApi.getInstance().flush(
      API_BASE_URL + "/flush",
      signature,
      formatStackTrace(getStackTrace())
    );
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
    const signature = `[android.location.LocationManager requestLocationUpdates] provider: ${provider}`;
    const description = `获取本地位置信息更新:参数为provider,minTimeMs,minDistanceM,listener,looper`;
    send(description);
    send(signature);
    printStackTrace(getStackTrace());
    InsightApi.getInstance().flush(
      API_BASE_URL + "/flush",
      description,
      formatStackTrace(getStackTrace())
    );
    InsightApi.getInstance().flush(
      API_BASE_URL + "/flush",
      signature,
      formatStackTrace(getStackTrace())
    );
    this.requestLocationUpdates(
      provider,
      minTimeMs,
      minDistanceM,
      listener,
      looper
    );
  };

  LocationManager.requestLocationUpdates.overload(
    "java.lang.String",
    "long",
    "float",
    "android.location.LocationListener"
  ).implementation = function (
    provider: any,
    minTimeMs: any,
    minDistanceM: any,
    listener: any
  ) {
    const signature = `[android.location.LocationManager requestLocationUpdates] provider: ${provider}`;
    const description = `获取本地位置信息更新:参数为provider,minTimeMs,minDistanceM,listener`;
    send(description);
    send(signature);
    printStackTrace(getStackTrace());
    InsightApi.getInstance().flush(
      API_BASE_URL + "/flush",
      description,
      formatStackTrace(getStackTrace())
    );
    InsightApi.getInstance().flush(
      API_BASE_URL + "/flush",
      signature,
      formatStackTrace(getStackTrace())
    );
    this.requestLocationUpdates(
      provider,
      minTimeMs,
      minDistanceM,
      listener
    );
  };

  LocationManager.requestLocationUpdates.overload(
    "android.location.LocationRequest",
    "android.app.PendingIntent"
  ).implementation = function (
    locationRequest: any,
    pendingIntent: any
  ) {
    const signature = `[android.location.LocationManager requestLocationUpdates] locationRequest: ${locationRequest}`;
    const description = `获取本地位置信息更新: 参数为locationRequest,pendingIntent`;
    send(description);
    send(signature);
    printStackTrace(getStackTrace());
    InsightApi.getInstance().flush(
      API_BASE_URL + "/flush",
      description,
      formatStackTrace(getStackTrace())
    );
    InsightApi.getInstance().flush(
      API_BASE_URL + "/flush",
      signature,
      formatStackTrace(getStackTrace())
    );
    this.requestLocationUpdates(
      locationRequest,
      pendingIntent
    );
  };

  LocationManager.requestLocationUpdates.overload(
    "android.location.LocationRequest",
    "java.util.concurrent.Executor",
    "android.location.LocationListener"
  ).implementation = function (
    locationRequest: any,
    executor: any,
    listener: any
  ) {
    const signature = `[android.location.LocationManager requestLocationUpdates] locationRequest: ${locationRequest}`;
    const description = `获取本地位置信息更新: 参数为locationRequest,executor,listener`;
    send(description);
    send(signature);
    printStackTrace(getStackTrace());
    InsightApi.getInstance().flush(
      API_BASE_URL + "/flush",
      description,
      formatStackTrace(getStackTrace())
    );
    InsightApi.getInstance().flush(
      API_BASE_URL + "/flush",
      signature,
      formatStackTrace(getStackTrace())
    );
    this.requestLocationUpdates(
      locationRequest,
      executor,
      listener
    );
  };

  LocationManager.requestLocationUpdates.overload(
    "android.location.LocationRequest",
    "android.location.LocationListener",
    "android.os.Looper"
  ).implementation = function (
    locationRequest: any,
    listener: any,
    looper: any
  ) {
    const signature = `[android.location.LocationManager requestLocationUpdates] locationRequest: ${locationRequest}`;
    const description = `获取本地位置信息更新: 参数为locationRequest,listener,looper`;
    send(description);
    send(signature);
    printStackTrace(getStackTrace());
    InsightApi.getInstance().flush(
      API_BASE_URL + "/flush",
      description,
      formatStackTrace(getStackTrace())
    );
    InsightApi.getInstance().flush(
      API_BASE_URL + "/flush",
      signature,
      formatStackTrace(getStackTrace())
    );
    this.requestLocationUpdates(
      locationRequest,
      listener,
      looper
    );
  };

  LocationManager.requestLocationUpdates.overload(
    "long",
    "float",
    "android.location.Criteria",
    "android.app.PendingIntent"
  ).implementation = function (
    minTimeMs: any,
    minDistanceM: any,
    criteria: any,
    pendingIntent: any
  ) {
    const signature = `[android.location.LocationManager requestLocationUpdates] minTimeMs: ${minTimeMs}`;
    const description = `获取本地位置信息更新: 参数为 minTimeMs,minDistanceM,criteria,pendingIntent`;
    send(description);
    send(signature);
    printStackTrace(getStackTrace());
    InsightApi.getInstance().flush(
      API_BASE_URL + "/flush",
      description,
      formatStackTrace(getStackTrace())
    );
    InsightApi.getInstance().flush(
      API_BASE_URL + "/flush",
      signature,
      formatStackTrace(getStackTrace())
    );
    this.requestLocationUpdates(
    minTimeMs,
    minDistanceM,
    criteria,
    pendingIntent
    );
  };

  LocationManager.requestLocationUpdates.overload(
    "java.lang.String",
    "long",
    "float",
    "android.app.PendingIntent"
  ).implementation = function (
    provider: any,
    minTimeMs: any,
    minDistanceM: any,
    pendingIntent: any
  ) {
    const signature = `[android.location.LocationManager requestLocationUpdates] provider: ${provider}`;
    const description = `获取本地位置信息更新: 参数为 provider,minTimeMs,minDistanceM,pendingIntent`;
    send(description);
    send(signature);
    printStackTrace(getStackTrace());
    InsightApi.getInstance().flush(
      API_BASE_URL + "/flush",
      description,
      formatStackTrace(getStackTrace())
    );
    InsightApi.getInstance().flush(
      API_BASE_URL + "/flush",
      signature,
      formatStackTrace(getStackTrace())
    );
    this.requestLocationUpdates(
    provider,
    minTimeMs,
    minDistanceM,
    pendingIntent
    );
  };

  LocationManager.requestLocationUpdates.overload(
    "long",
    "float",
    "android.location.Criteria",
    "java.util.concurrent.Executor",
    "android.location.LocationListener"
  ).implementation = function (
    minTimeMs: any,
    minDistanceM: any,
    criteria: any,
    executor: any,
    listener: any
  ) {
    const signature = `[android.location.LocationManager requestLocationUpdates] minTimeMs: ${minTimeMs}`;
    const description = `获取本地位置信息更新: 参数为  minTimeMs,minDistanceM,criteria,executor,listener`;
    send(description);
    send(signature);
    printStackTrace(getStackTrace());
    InsightApi.getInstance().flush(
      API_BASE_URL + "/flush",
      description,
      formatStackTrace(getStackTrace())
    );
    InsightApi.getInstance().flush(
      API_BASE_URL + "/flush",
      signature,
      formatStackTrace(getStackTrace())
    );
    this.requestLocationUpdates(
      minTimeMs,
      minDistanceM,
      criteria,
      executor,
      listener
    );
  };

  LocationManager.requestLocationUpdates.overload(
    "long",
    "float",
    "android.location.Criteria",
    "android.location.LocationListener",
    "android.os.Looper"
  ).implementation = function (
    minTimeMs: any,
    minDistanceM: any,
    criteria: any,
    listener: any,
    looper: any
  ) {
    const signature = `[android.location.LocationManager requestLocationUpdates] minTimeMs: ${minTimeMs}`;
    const description = `获取本地位置信息更新: 参数为  minTimeMs,minDistanceM,criteria,listener,looper`;
    send(description);
    send(signature);
    printStackTrace(getStackTrace());
    InsightApi.getInstance().flush(
      API_BASE_URL + "/flush",
      description,
      formatStackTrace(getStackTrace())
    );
    InsightApi.getInstance().flush(
      API_BASE_URL + "/flush",
      signature,
      formatStackTrace(getStackTrace())
    );
    this.requestLocationUpdates(
      minTimeMs,
      minDistanceM,
      criteria,
      listener,
      looper
    );
  };

  LocationManager.requestLocationUpdates.overload(
    "java.lang.String",
    "long",
    "float",
    "java.util.concurrent.Executor",
    "android.location.LocationListener"
  ).implementation = function (
    provider: any,
    minTimeMs: any,
    minDistanceM: any,
    executor: any,
    listener: any
  ) {
    const signature = `[android.location.LocationManager requestLocationUpdates] minTimeMs: ${minTimeMs}`;
    const description = `获取本地位置信息更新: 参数为 provider, minTimeMs,minDistanceM,executor,listener`;
    send(description);
    send(signature);
    printStackTrace(getStackTrace());
    InsightApi.getInstance().flush(
      API_BASE_URL + "/flush",
      description,
      formatStackTrace(getStackTrace())
    );
    InsightApi.getInstance().flush(
      API_BASE_URL + "/flush",
      signature,
      formatStackTrace(getStackTrace())
    );
    this.requestLocationUpdates(
      provider,
      minTimeMs,
      minDistanceM,
      executor,
      listener
    );
  };



  LocationManager.getLastKnownLocation.implementation = function (
    provider: any
  ) {
    const signature = `[android.location.LocationManager getLastKnownLocation] provider: ${provider}`;
    send(signature);
    printStackTrace(getStackTrace());
    InsightApi.getInstance().flush(
      API_BASE_URL + "/flush",
      signature,
      formatStackTrace(getStackTrace())
    );
    return this.getLastKnownLocation(provider);
  };
  //#endregion

  //#region android.app.ApplicationPackageManager
  const ApplicationPackageManager = Java.use(
    "android.app.ApplicationPackageManager"
  );
  ApplicationPackageManager.getPackageInfoAsUser.overload(
    "java.lang.String",
    "int",
    "int"
  ).implementation = function (packageName: any, flags: any, userId: any) {
    const signature = `[android.app.ApplicationPackageManager getPackageInfoAsUser] packageName: ${packageName}, flags: ${flags}, userId: ${userId}`;
    send(signature);
    printStackTrace(getStackTrace());
    InsightApi.getInstance().flush(
      API_BASE_URL + "/flush",
      signature,
      formatStackTrace(getStackTrace())
    );
    return this.getPackageInfoAsUser(packageName, flags, userId);
  };
  //#endregion
});
