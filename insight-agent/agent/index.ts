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
    //#region java.io.RandomAccessFile
    const RandomAccessFile = Java.use('java.io.RandomAccessFile')
    RandomAccessFile
        .$init
        .overload('java.io.File', 'java.lang.String')
        .implementation = function (file: string, mode) {
            if (!file.toString().startsWith('/storage/emulated/0/Android/data')) {
                send(`[java.io.RandomAccessFile $init] file: ${file}, mode: ${mode}`)
                printStackTrace()
            }
            this.$init(file, mode)
        }
    RandomAccessFile
        .$init
        .overload('java.lang.String', 'java.lang.String')
        .implementation = function (name: string, mode) {
            if (!name.startsWith('/storage/emulated/0/Android/data')) {
                send(`[java.io.RandomAccessFile $init] name: ${name}, mode: ${mode}`)
                printStackTrace()
            }
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
})