import { log } from "./logger"

const header = Memory.alloc(16)
header
    .writeU32(0xdeadbeef).add(4)
    .writeU32(0xd00ff00d).add(4)
    .writeU64(uint64("0x1122334455667788"))
log(hexdump(header.readByteArray(16) as ArrayBuffer, { ansi: true }))

Process.getModuleByName("libfrida-gadget.so")
    .enumerateExports()
    .slice(0, 16)
    .forEach((exp, index) => {
        log(`export ${index}: ${exp.name}`)
    })

// Interceptor.attach(Module.getExportByName(null, "open"), {
//     onEnter(args) {
//         const path = args[0].readUtf8String()
//         log(`open() path="${path}"`)
//     }
// })

function printStackTrace() {
    const Thread = Java.use('java.lang.Thread')
    const thread = Thread.currentThread()
    log(thread.getStackTrace())
}

Java.perform(() => {
    const ActivityThread = Java.use('android.app.ActivityThread')
    const processName = ActivityThread.currentProcessName()
    log(processName)
    const dangerDirectories = [
        '/data/user/0/' + processName + '/lib-main/'
    ]

    //#region java.io.RandomAccessFile
    const RandomAccessFile = Java.use('java.io.RandomAccessFile')
    RandomAccessFile
        .$init
        .overload('java.io.File', 'java.lang.String')
        .implementation = function (file: string, mode) {
            dangerDirectories.forEach(dangerDirectory => {
                if (file.toString().startsWith(dangerDirectory)) {
                    send(`[java.io.RandomAccessFile $init] file: ${file}, mode: ${mode}`)
                    printStackTrace()
                }
            });
            this.$init(file, mode)
        }
    RandomAccessFile
        .$init
        .overload('java.lang.String', 'java.lang.String')
        .implementation = function (name: string, mode) {
            dangerDirectories.forEach(dangerDirectory => {
                if (name.startsWith(dangerDirectory)) {
                    send(`[java.io.RandomAccessFile $init] name: ${name}, mode: ${mode}`)
                    printStackTrace()
                }
            });
            this.$init(name, mode)
        }
    //#endregion

    //#region android.app.ActivityManager
    const ActivityManager = Java.use('android.app.ActivityManager')
    ActivityManager
        .getRunningAppProcesses
        .implementation = function () {
            send(`[android.app.ActivityManager getRunningAppProcesses]`)
            printStackTrace()
            return this.getRunningAppProcesses()
        }
    //#endregion

    //#region java.net.NetworkInterface
    const NetworkInterface = Java.use('java.net.NetworkInterface')
    NetworkInterface
        .getHardwareAddress
        .implementation = function () {
            send(`[java.net.NetworkInterface getHardwareAddress]`)
            printStackTrace()
            return this.getHardwareAddress()
        }
    //#endregion

    //#region java.io.FileOutputStream
    const FileOutputStream = Java.use('java.io.FileOutputStream')
    FileOutputStream
        .$init
        .overload('java.io.File')
        .implementation = function (file) {
            send(`[java.io.FileOutputStream $init] file: ${file}`)
            printStackTrace()
            this.$init(file)
        }
    //#endregion

    //#region android.provider.Settings$Secure
    const Secure = Java.use('android.provider.Settings$Secure')
    Secure
        .getStringForUser
        .overload('android.content.ContentResolver', 'java.lang.String', 'int')
        .implementation = function (contentResolver: any, name: string, userHandle: number) {
            send(`[android.provider.Settings$Secure getStringForUser] contentResolver: ${contentResolver}, name: ${name}, userHandle: ${userHandle}`)
            printStackTrace()
            return this.getStringForUser(contentResolver, name, userHandle)
        }
    //#endregion
})