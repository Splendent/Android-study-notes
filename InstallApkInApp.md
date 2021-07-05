# Install Apk in app
## 目的
為了做一款android TV的`home app(user習慣稱作launcher的app i.e., nova launcher)`，在app初次啟動時需要從網路安裝一些基本的APK，卻發生了無法照著網路教學安裝的問題

## 實作
本次開發的機器對象為android 10以上，所以有許多的參考已經不可用、並且需要考慮下載路徑的問題

參考並修改的部分如下
- kotlin
- 在該blog中有其他設置(`setPermission`)，但經測試後發現沒有必要，文件也沒有看到相關需求
- manifest設置額外的file provider path應該也是不需要的，因徹頭徹尾都沒有存取過外部資料夾

[Android studio 使用原生自带DownloadManager实现app下载更新](https://blog.csdn.net/liufatao/article/details/54583136?utm_medium=distribute.pc_relevant_download.none-task-blog-2~default~BlogCommendFromBaidu~default-7.nonecase&depth_1-utm_source=distribute.pc_relevant_download.none-task-blog-2~default~BlogCommendFromBaidu~default-7.nonecas)

```kotlin
class ApkDownloadHelper(val context: Context,val fragment: Fragment) {
    val TAG = "ApkDownloadHelper"
    interface PermissionListener {
        fun onGranted()
        fun onDenied(permissions: List<String>)
    }
    private var mPermissionListener : PermissionListener? = null
    private fun handlePermissions(permissions: Array<String>, listener: PermissionListener) {
        mPermissionListener = listener
        val requestPermissionList: MutableList<String> = ArrayList()
        for (permission in permissions) {
            if (ContextCompat.checkSelfPermission(context, permission) != PackageManager.PERMISSION_GRANTED) {
                requestPermissionList.add(permission)
            }
        }
        if (requestPermissionList.isNotEmpty()) {
            fragment.requestPermissions(permissions, 1)
        } else if (listener != null) {
            listener.onGranted()
        }
    }


    fun onRequestPermissionsResult(requestCode: Int, permissions: Array<String>, grantResults: IntArray) {
        if (requestCode == 1) {
            if (grantResults.isNotEmpty()) {
                val deniedPermissions: MutableList<String> = ArrayList()
                for (i in grantResults.indices) {
                    val grantResult = grantResults[i]
                    val permission = permissions[i]
                    if (grantResult != PackageManager.PERMISSION_GRANTED) {
                        deniedPermissions.add(permission)
                    }
                }
                if (deniedPermissions.isEmpty()) {
                    mPermissionListener?.onGranted()
                } else {
                    mPermissionListener?.onDenied(deniedPermissions.toList())
                }
            }
        }
    }


    fun openAPK(content: Uri) {
        var apkfile = File(content.toString())
        var mIntent = Intent(Intent.ACTION_VIEW)
        mIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        //判讀版本是否在7.0以上
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            mIntent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            mIntent.setDataAndType(content, "application/vnd.android.package-archive")
        } else {
            mIntent.setDataAndType(Uri.fromFile(apkfile), "application/vnd.android.package-archive")
        }
        context.startActivity(mIntent)
    }

    fun downloadApk(dowloadPath: String) {
        Log.d(TAG,"dowloadPath $dowloadPath")
        handlePermissions(
            arrayOf(
                android.Manifest.permission.READ_EXTERNAL_STORAGE,
                android.Manifest.permission.WRITE_EXTERNAL_STORAGE
            ), object : PermissionListener {

                override fun onGranted() {
                    try {
                        val dManager: DownloadManager = context.getSystemService(Context.DOWNLOAD_SERVICE) as DownloadManager
                        var uri: Uri = Uri.parse(dowloadPath)
                        var request: DownloadManager.Request = DownloadManager.Request(uri)
                        request.setAllowedNetworkTypes(DownloadManager.Request.NETWORK_WIFI or DownloadManager.Request.NETWORK_MOBILE)

                        // 设置下载路径和文件名
                        // SP: 此處用不到，不需要移至外部資料夾
                        // request.setDestinationInExternalPublicDir(Environment.DIRECTORY_DOWNLOADS, "Apk.apk")

                        request.setDescription("Downloading")
                        request.setNotificationVisibility(DownloadManager.Request.VISIBILITY_VISIBLE_NOTIFY_COMPLETED)
                        request.setMimeType("application/vnd.android.package-archive")
                        // 设置为可被媒体扫描器找到
                        // SP: deprecated
                        request.allowScanningByMediaScanner() 
                        // 设置为可见和可管理
                        request.setVisibleInDownloadsUi(true) 
                        // 获取此次下载的ID
                        var refernece = dManager.enqueue(request) 
                        // 注册广播接收器，当下载完成时自动安装
                        var filter: IntentFilter = IntentFilter(DownloadManager.ACTION_DOWNLOAD_COMPLETE)
                        var receiver: BroadcastReceiver = object : BroadcastReceiver() {
                            override fun onReceive(context: Context?, intent: Intent?) {
                                Log.d(TAG, "onReceive!!!")
                                var myDwonloadID = intent?.getLongExtra(DownloadManager.EXTRA_DOWNLOAD_ID, -1)
                                if (refernece == myDwonloadID) {
                                    var downloadFileUri = dManager.getUriForDownloadedFile(refernece)
                                    //SP: 取得的是 content: 開頭的scheme
                                    Log.d(TAG, "downloadFileUri:   {$downloadFileUri}")
                                    if (downloadFileUri != null) {
                                        openAPK(downloadFileUri)
                                    }

                                }
                            }
                        }
                        context.registerReceiver(receiver, filter)
                    }
                    catch (e : Exception) {
                        Log.d(TAG,"download exception", e)
                    }
                }

                override fun onDenied(deniedPermissions: List<String>) {
                    Toast.makeText(context, "No Permisson!", Toast.LENGTH_LONG).show()
                }
            }
        )
    }
}
```
其他ref:

[Android 使用DownloadManager進行版本更新的完整方案
](https://blog.csdn.net/sinat_33195772/article/details/70237593?utm_medium=distribute.pc_relevant_download.none-task-blog-baidujs-3.nonecase&depth_1-utm_source=distribute.pc_relevant_download.none-task-blog-baidujs-3.nonecase)

[Android: install .apk programmatically [duplicate]](https://stackoverflow.com/questions/4967669/android-install-apk-programmatically)

## 問題
安裝時會跳出解析套件時出現問題，去看logcat error msg沒挖到任何東西，只好朝其他訊息下手

system log
```ruby
2021-06-23 18:01:33.346 2517-5528/system_process E/NotificationService: Package has already posted or enqueued 27 notifications.  Not showing more.  package=com.android.providers.downloads
2021-06-23 18:01:33.349 2517-3786/system_process E/NotificationService: Package has already posted or enqueued 26 notifications.  Not showing more.  package=com.android.providers.downloads
2021-06-23 18:01:33.398 2517-3786/system_process E/NotificationService: Package has already posted or enqueued 26 notifications.  Not showing more.  package=com.android.providers.all_downloads
...
2021-06-23 18:01:42.367 2517-3144/system_process E/NotificationService: Package has already posted or enqueued 27 notifications.  Not showing more.  package=com.android.providers.downloads
2021-06-23 18:01:42.370 2517-2857/system_process E/NotificationService: Package has already posted or enqueued 27 notifications.  Not showing more.  package=com.android.providers.downloads
2021-06-23 18:01:42.395 3110-3392/android.process.media E/DatabaseUtils: Writing exception to parcel
    java.lang.SecurityException: Permission Denial: reading com.android.providers.downloads.DownloadProvider uri content://downloads/all_downloads/168 from pid=4337, uid=10009 requires android.permission.ACCESS_ALL_DOWNLOADS, or grantUriPermission()
        at android.content.ContentProvider.enforceReadPermissionInner(ContentProvider.java:729)
        at android.content.ContentProvider$Transport.enforceReadPermission(ContentProvider.java:602)
        at android.content.ContentProvider$Transport.enforceFilePermission(ContentProvider.java:593)
        at android.content.ContentProvider$Transport.openTypedAssetFile(ContentProvider.java:507)
        at android.content.ContentProviderNative.onTransact(ContentProviderNative.java:307)
        at android.os.Binder.execTransactInternal(Binder.java:1021)
        at android.os.Binder.execTransact(Binder.java:994)
        ...
2021-06-23 18:01:43.333 2517-5694/system_process E/NotificationService: Package has already posted or enqueued 26 notifications.  Not showing more.  package=com.android.providers.downloads
2021-06-23 18:01:43.335 2517-5694/system_process E/NotificationService: Package has already posted or enqueued 27 notifications.  Not showing more.  package=com.android.providers.downloads
2021-06-23 18:01:48.390 13608-13608/? E/ion: ioctl c0044901 failed with code -1: Not a typewriter
2021-06-23 18:02:01.607 2177-2177/? E//vendor/bin/hw/android.hardware.health@2.0-service: /sys/block/sda/stat: ReadFileToString failed.
2021-06-23 18:02:21.560 2177-2177/? E//vendor/bin/hw/android.hardware.health@2.0-service: /sys/block/sda/stat: ReadFileToString failed.
```

app log
```ruby
2021-06-23 18:01:33.244 13466-13466/com.launchertv.debug D/ApkDownloadHelper: dowloadPath http://dldir1.qq.com/qqmi/aphone_lite/upgradepkg/VideoLite_V1.5.0.20045.apk
2021-06-23 18:01:42.270 13466-13466/com.launchertv.debug D/ApkDownloadHelper: onReceive!!! [I@ca6efbb
2021-06-23 18:01:42.280 13466-13466/com.launchertv.debug D/ApkDownloadHelper: downloadFileUri:   {content://downloads/all_downloads/168}
2021-06-23 18:01:42.397 4337-4371/com.android.packageinstaller W/InstallStaging: Error staging apk from content URI
    java.lang.SecurityException: Permission Denial: reading com.android.providers.downloads.DownloadProvider uri content://downloads/all_downloads/168 from pid=4337, uid=10009 requires android.permission.ACCESS_ALL_DOWNLOADS, or grantUriPermission()
        at android.os.Parcel.createException(Parcel.java:2071)
        at android.os.Parcel.readException(Parcel.java:2039)
        at android.database.DatabaseUtils.readExceptionFromParcel(DatabaseUtils.java:188)
        at android.database.DatabaseUtils.readExceptionWithFileNotFoundExceptionFromParcel(DatabaseUtils.java:151)
        at android.content.ContentProviderProxy.openTypedAssetFile(ContentProviderNative.java:705)
        at android.content.ContentResolver.openTypedAssetFileDescriptor(ContentResolver.java:1687)
        at android.content.ContentResolver.openAssetFileDescriptor(ContentResolver.java:1503)
        at android.content.ContentResolver.openInputStream(ContentResolver.java:1187)
        at com.android.packageinstaller.InstallStaging$StagingAsyncTask.doInBackground(InstallStaging.java:174)
        at com.android.packageinstaller.InstallStaging$StagingAsyncTask.doInBackground(InstallStaging.java:167)
        at android.os.AsyncTask$3.call(AsyncTask.java:378)
        at java.util.concurrent.FutureTask.run(FutureTask.java:266)
        at android.os.AsyncTask$SerialExecutor$1.run(AsyncTask.java:289)
        at java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1167)
        at java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:641)
        at java.lang.Thread.run(Thread.java:919)
```

混合的log(判斷時間點用)
```ruby
2021-06-23 18:01:42.270 13466-13466/com.launchertv.debug D/ApkDownloadHelper: onReceive!!! [I@ca6efbb
2021-06-23 18:01:42.270 2517-2787/system_process E/NotificationService: Package has already posted or enqueued 26 notifications.  Not showing more.  package=com.android.providers.downloads
2021-06-23 18:01:42.274 2517-3144/system_process E/NotificationService: Package has already posted or enqueued 26 notifications.  Not showing more.  package=com.android.providers.downloads
2021-06-23 18:01:42.277 2517-3144/system_process E/NotificationService: Package has already posted or enqueued 26 notifications.  Not showing more.  package=com.android.providers.downloads
2021-06-23 18:01:42.280 2517-2787/system_process E/NotificationService: Package has already posted or enqueued 26 notifications.  Not showing more.  package=com.android.providers.downloads
2021-06-23 18:01:42.280 13466-13466/com.launchertv.debug D/ApkDownloadHelper: downloadFileUri:   {content://downloads/all_downloads/168}
2021-06-23 18:01:42.281 2517-3144/system_process I/ActivityTaskManager: START u0 {act=android.intent.action.VIEW dat=content://downloads/all_downloads/168 typ=application/vnd.android.package-archive flg=0x10000001 cmp=com.android.packageinstaller/.InstallStart} from uid 1000
2021-06-23 18:01:42.282 2517-2787/system_process E/NotificationService: Package has already posted or enqueued 26 notifications.  Not showing more.  package=com.android.providers.downloads
2021-06-23 18:01:42.287 2517-2787/system_process I/chatty: uid=1000(system) Binder:2517_5 identical 1 line
2021-06-23 18:01:42.290 2517-2787/system_process E/NotificationService: Package has already posted or enqueued 26 notifications.  Not showing more.  package=com.android.providers.downloads
2021-06-23 18:01:42.290 2517-3144/system_process W/UriGrantsManagerService: For security reasons, the system cannot issue a Uri permission grant to content://downloads/all_downloads/168 [user 0]; use startActivityAsCaller() instead
```

可以看到幾個關鍵點
1. URI權限需求 `requires android.permission.ACCESS_ALL_DOWNLOADS, or grantUriPermission()`
```
E/DatabaseUtils: Writing exception to parcel
    java.lang.SecurityException: Permission Denial: reading com.android.providers.downloads.DownloadProvider uri content://downloads/all_downloads/168 from pid=4337, uid=10009 requires android.permission.ACCESS_ALL_DOWNLOADS, or grantUriPermission()
        at android.content.ContentProvider.enforceReadPermissionInner(ContentProvider.java:729)
        at android.content.ContentProvider$Transport.enforceReadPermission(ContentProvider.java:602)
        at android.content.ContentProvider$Transport.enforceFilePermission(ContentProvider.java:593)
        at android.content.ContentProvider$Transport.openTypedAssetFile(ContentProvider.java:507)
        at android.content.ContentProviderNative.onTransact(ContentProviderNative.java:307)
        at android.os.Binder.execTransactInternal(Binder.java:1021)
        at android.os.Binder.execTransact(Binder.java:994)
```
2. URI權限需求 `requires android.permission.ACCESS_ALL_DOWNLOADS, or grantUriPermission()`
```
com.android.packageinstaller W/InstallStaging: Error staging apk from content URI
    java.lang.SecurityException: Permission Denial: reading com.android.providers.downloads.DownloadProvider uri content://downloads/all_downloads/168 from pid=4337, uid=10009 requires android.permission.ACCESS_ALL_DOWNLOADS, or grantUriPermission()
```
3. 以系統權限啟動安裝Intent `act=android.intent.action.VIEW dat=content://downloads/all_downloads/168... from uid 1000`
```
 system_process I/ActivityTaskManager: START u0 {act=android.intent.action.VIEW dat=content://downloads/all_downloads/168 typ=application/vnd.android.package-archive flg=0x10000001 cmp=com.android.packageinstaller/.InstallStart} from uid 1000
```
4. 無法啟動URI PERMISSION `cannot issue a Uri permission grant to content://downloads/all_downloads/168`
```
 system_process W/UriGrantsManagerService: For security reasons, the system cannot issue a Uri permission grant to content://downloads/all_downloads/168 [user 0]; use startActivityAsCaller() instead
```

因此可確定因為自身APP有系統權限，而無法用參考中的方式去啟動安裝APK的Intent

參考了[Android O（android 8.1） SYSTEM_UID應用無法使用FileProvider](https://blog.csdn.net/cau_eric/article/details/99859756)跟[Android android.uid.system的应用调用安装apk失败](https://blog.csdn.net/u012894808/article/details/106712151)均表示需要去修改AOSP的code，但是這樣嚴重違反了安全協議，故不採用


決定從其他地方下手，先看過AOSP的[來源](https://android.googlesource.com/platform/frameworks/base/+/master/services/core/java/com/android/server/uri/UriGrantsManagerService.java)
```java
  // Bail early if system is trying to hand out permissions directly; it
        // must always grant permissions on behalf of someone explicit.
        final int callingAppId = UserHandle.getAppId(callingUid);
        if ((callingAppId == SYSTEM_UID) || (callingAppId == ROOT_UID)) {
            if ("com.android.settings.files".equals(grantUri.uri.getAuthority())
                    || "com.android.settings.module_licenses".equals(grantUri.uri.getAuthority())) {
                // Exempted authority for
                // 1. cropping user photos and sharing a generated license html
                //    file in Settings app
                // 2. sharing a generated license html file in TvSettings app
                // 3. Sharing module license files from Settings app
            } else {
                Slog.w(TAG, "For security reasons, the system cannot issue a Uri permission"
                        + " grant to " + grantUri + "; use startActivityAsCaller() instead");
                return -1;
            }
        }
```
確定了只要是系統的`Intent`在`grantURIPermission`的時候都碰到這個問題，因此思考方向分成兩個
1. 觸發其他`Activity/APK`去安裝
2. 尋找不用`Intent`去安裝的方式

## 解1 - 觸發其他Activity/APK去安裝
參考[Sending the user to another app](https://developer.android.com/training/basics/intents/sending)
利用`Extra`傳送apk url去交給別隻APK下載並觸發安裝`Intent`即可
```kotlin
val url = "http://dldir1.qq.com/qqmi/aphone_lite/upgradepkg/VideoLite_V1.5.0.20045.apk"
val intent = getLaunchIntentForPackage("com.whatever.android.updater.app")
intent?.putExtra("URLs", arrayOf(url))
context?.startActivity(intent)
```
## 解2 - 尋找不用Intent去安裝的方式
利用[PackageInstaller](https://developer.android.com/reference/android/content/pm/PackageInstaller)
AOSP上也有[SAMPLE - InstallApkSession](https://android.googlesource.com/platform/development/+/master/samples/ApiDemos/src/com/example/android/apis/content/InstallApkSessionApi.java)可以參考

需要特別處理的就是SAMPLE是用`IOSTREAM`，但`DownloadManager`提供的是`URI`，需要再多轉一手`activity.contentResolver.openInputStream(uri)`
```kotlin
object InstallApk {
    const val PACKAGE_INSTALLED_ACTION = "com.example.android.apis.content.SESSION_API_PACKAGE_INSTALLED"
    const val TAG = "InstallApk"
    fun install(activity: Activity, uri : Uri) {
        var session: PackageInstaller.Session? = null
        try {
            val packageInstaller: PackageInstaller = activity.packageManager.packageInstaller
            val params = SessionParams(
                SessionParams.MODE_FULL_INSTALL
            )
            val sessionId = packageInstaller.createSession(params)
            session = packageInstaller.openSession(sessionId)
            addApkToInstallSession(activity, uri, session) // Create an install status receiver.

            val intent = Intent(activity, activity.javaClass)
            intent.action = PACKAGE_INSTALLED_ACTION
            intent.flags = Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP
            val pendingIntent = PendingIntent.getActivity(activity, 0, intent, 0)
            val statusReceiver = pendingIntent.intentSender // Commit the session (this will start the installation workflow).
            Log.d(TAG,"commit session")
            session.commit(statusReceiver)
        } catch (e: IOException) {
            throw RuntimeException("Couldn't install package", e)
        } catch (e: RuntimeException) {
            session?.abandon()
            throw e
        }
    }

    private fun addApkToInstallSession(activity: Activity, uri: Uri, session: PackageInstaller.Session) { // It's recommended to pass the file size to openWrite(). Otherwise installation may fail
        // if the disk is almost full.
        session.openWrite("package", 0, -1).use { packageInSession ->
            Log.d(TAG,"openWrite")
            activity.contentResolver.openInputStream(uri).use { inputStream ->
                Log.d(TAG,"openWrite IN")
                val buffer = ByteArray(16384)
                var n = 0
                while (inputStream?.read(buffer)?.also { n = it }?:-1 >= 0) {
                    Log.d(TAG,"read/write buffer")
                    packageInSession.write(buffer, 0, n)
                }
            }
        }
    }
}
```

取得安裝狀態/通知的部分，因我是採用`signle activity`架構，須另外掛在`main activity`底下
```kotlin
    // Note: this Activity must run in singleTop launchMode for it to be able to receive the intent
    // in onNewIntent().
    override fun onNewIntent(intent: Intent) {
        Log.d(TAG,"onNewIntent:${intent}-${intent.extras}")
        super.onNewIntent(intent)
        val extras = intent.extras
        if (InstallApk.PACKAGE_INSTALLED_ACTION == intent.action) {
            val status = extras!!.getInt(PackageInstaller.EXTRA_STATUS)
            val message = extras.getString(PackageInstaller.EXTRA_STATUS_MESSAGE)
            Log.d(InstallApk.TAG,"${intent.action}-$status-$message")
            when (status) {
                PackageInstaller.STATUS_PENDING_USER_ACTION -> { // This test app isn't privileged, so the user has to confirm the install.
                    val confirmIntent = extras[Intent.EXTRA_INTENT] as Intent?
                    startActivity(confirmIntent)
                }
                PackageInstaller.STATUS_SUCCESS -> Toast.makeText(this, "Install succeeded!", Toast.LENGTH_SHORT).show()
                PackageInstaller.STATUS_FAILURE, PackageInstaller.STATUS_FAILURE_ABORTED, PackageInstaller.STATUS_FAILURE_BLOCKED, PackageInstaller.STATUS_FAILURE_CONFLICT, PackageInstaller.STATUS_FAILURE_INCOMPATIBLE, PackageInstaller.STATUS_FAILURE_INVALID, PackageInstaller.STATUS_FAILURE_STORAGE -> Toast.makeText(
                    this, "Install failed! $status, $message", Toast.LENGTH_SHORT
                ).show()
                else -> Toast.makeText(
                    this, "Unrecognized status received from installer: $status", Toast.LENGTH_SHORT
                ).show()
            }
        }
    }
```

其他Ref:

https://codertw.com/%E7%A8%8B%E5%BC%8F%E8%AA%9E%E8%A8%80/461172/

https://kknews.cc/zh-tw/code/okbmrvq.html