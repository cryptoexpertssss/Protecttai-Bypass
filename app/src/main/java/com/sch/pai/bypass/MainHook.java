package com.sch.pai.bypass;

import android.app.Application;
import android.content.Context;
import android.content.pm.ApplicationInfo;

import java.lang.reflect.Method;
import java.util.Enumeration;

import dalvik.system.DexFile;
import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XC_MethodReplacement;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class MainHook implements IXposedHookLoadPackage {
    
    // The "Digital Fingerprint" of RASP SDK initialization patterns
    private static final Class<?>[][] RASP_INIT_SIGNATURES = {
        {String.class, int.class, int.class, int.class, String.class, int.class},
        {Context.class, String.class, int.class, int.class, int.class, String.class, int.class}
    };


    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {
        // Run defensive hooks immediately to hide LSPosed
        XposedBridge.log("ShekharPAIBypass: [DEBUG] handleLoadPackage started for " + lpparam.packageName);
        runDefensiveHooks(lpparam);

        XposedBridge.log("ShekharPAIBypass: Loaded for " + lpparam.packageName);

        try {
            // We run the scanner as early as possible in handleLoadPackage
            // using the appInfo sourceDir instead of waiting for Application.onCreate
            if (lpparam.appInfo != null) {
                // RUN FOR ALL PACKAGES - No more TARGET_PACKAGES check
                runUniversalScanner(lpparam.packageName, lpparam.appInfo.sourceDir, lpparam.classLoader);
            }
        } catch (Throwable t) {
            XposedBridge.log("ShekharPAIBypass: Early universal scanner failed: " + t.getMessage());
        }

        try {
            XposedHelpers.findAndHookMethod(Application.class, "onCreate", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    try {
                        Context context = (Context) param.thisObject;
                        XposedBridge.log("ShekharPAIBypass: Late-phase scan check for " + context.getPackageName());
                        // runUniversalScanner(context.getApplicationInfo().sourceDir, context.getClassLoader());
                    } catch (Throwable t) {
                        XposedBridge.log("ShekharPAIBypass: Error in late-phase check: " + t.getMessage());
                    }
                }
            });
        } catch (Throwable t) {
            XposedBridge.log("ShekharPAIBypass: Failed to hook Application.onCreate: " + t.getMessage());
        }
    }

    private void runDefensiveHooks(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            // 1. Spoof PackageManager to hide LSPosed Manager
            XposedHelpers.findAndHookMethod("android.app.ApplicationPackageManager", lpparam.classLoader, "getPackageInfo", String.class, int.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    String packageName = (String) param.args[0];
                    if (packageName != null && (packageName.contains("lsposed") || packageName.equals("io.github.lsposed.manager"))) {
                        XposedBridge.log("ShekharPAIBypass: [DEFENCE] Intercepted getPackageInfo for " + packageName);
                        param.setThrowable(new android.content.pm.PackageManager.NameNotFoundException(packageName));
                    }
                }
            });

            // 2. Sanitize Stack Traces to hide Xposed classes
            XposedHelpers.findAndHookMethod(Throwable.class, "getStackTrace", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    StackTraceElement[] stackTrace = (StackTraceElement[]) param.getResult();
                    if (stackTrace != null) {
                        java.util.List<StackTraceElement> cleanTrace = new java.util.ArrayList<>();
                        boolean modified = false;
                        for (StackTraceElement element : stackTrace) {
                            String className = element.getClassName();
                            if (className.contains("de.robv.android.xposed") || 
                                className.contains("LSPHooker") || 
                                className.contains("me.weishu.epic") ||
                                className.contains("com.sch.pai.bypass")) {
                                modified = true;
                                continue;
                            }
                            cleanTrace.add(element);
                        }
                        if (modified) {
                            param.setResult(cleanTrace.toArray(new StackTraceElement[0]));
                        }
                    }
                }
            });

            // 3. Hide Virtual Xposed properties and Proxy properties
            XposedHelpers.findAndHookMethod(System.class, "getProperty", String.class, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    String key = (String) param.args[0];
                    if (key != null) {
                        if (key.equals("vxp") || key.equals("ro.secure")) {
                            if (key.equals("ro.secure")) param.setResult("1");
                            else param.setResult(null);
                        } else if (key.equals("ro.debuggable")) {
                            param.setResult("0");
                        } else if (key.equals("http.proxyHost") || key.equals("http.proxyPort") || 
                                   key.equals("https.proxyHost") || key.equals("https.proxyPort")) {
                            XposedBridge.log("ShekharPAIBypass: [DEFENCE] Hid proxy system property: " + key);
                            param.setResult(null);
                        }
                    }
                }
            });

            // 4. Prevent App from wiping its own data (Protectt.ai RASP defense)
            XposedHelpers.findAndHookMethod("android.app.ActivityManager", lpparam.classLoader, "clearApplicationUserData", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    XposedBridge.log("ShekharPAIBypass: [DEFENCE] Blocked clearApplicationUserData!");
                    param.setResult(true); // Pretend it succeeded
                }
            });

            // 5. Prevent System.exit()
            XposedHelpers.findAndHookMethod("java.lang.System", lpparam.classLoader, "exit", int.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    XposedBridge.log("ShekharPAIBypass: [DEFENCE] Blocked System.exit(" + param.args[0] + ")");
                    param.setResult(null); // Block exit
                }
            });

            // 6. Prevent Process.killProcess()
            XposedHelpers.findAndHookMethod("android.os.Process", lpparam.classLoader, "killProcess", int.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    int pid = (int) param.args[0];
                    if (pid == android.os.Process.myPid()) {
                        XposedBridge.log("ShekharPAIBypass: [DEFENCE] Blocked Process.killProcess(" + pid + ")");
                        param.setResult(null); // Block killProcess for our own PID
                    }
                }
            });

            // 6.5. Prevent File.exists() for Root binaries and apps
            XposedHelpers.findAndHookMethod(java.io.File.class, "exists", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    java.io.File file = (java.io.File) param.thisObject;
                    String path = file.getAbsolutePath();
                    if (path != null) {
                        String lower = path.toLowerCase();
                        if (lower.contains("su") || lower.contains("magisk") || lower.contains("xposed") ||
                            lower.contains("edxposed") || lower.contains("lsposed") || lower.contains("riru") ||
                            lower.contains("zygisk") || lower.contains("busybox") || lower.contains("supersu")) {
                            
                            // Check exact matches or common paths
                            if (lower.equals("/system/app/superuser.apk") || lower.equals("/sbin/su") ||
                                lower.equals("/system/bin/su") || lower.equals("/system/xbin/su") ||
                                lower.equals("/data/local/xbin/su") || lower.equals("/data/local/bin/su") ||
                                lower.equals("/system/sd/xbin/su") || lower.equals("/system/bin/failsafe/su") ||
                                lower.equals("/data/local/su") || lower.equals("/su/bin/su") ||
                                lower.contains("magisk") || lower.contains("lsposed") || lower.contains("zygisk")) {
                                
                                XposedBridge.log("ShekharPAIBypass: [DEFENCE] Blocked Root File check: " + path);
                                param.setResult(false);
                            }
                        }
                    }
                }
            });

            // 6.6. Hide from getInstalledPackages and getInstalledApplications
            XC_MethodHook packageListHook = new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    java.util.List<?> list = (java.util.List<?>) param.getResult();
                    if (list != null) {
                        java.util.List<Object> cleanList = new java.util.ArrayList<>();
                        boolean modified = false;
                        for (Object info : list) {
                            String pkgName = null;
                            if (info instanceof android.content.pm.PackageInfo) {
                                pkgName = ((android.content.pm.PackageInfo) info).packageName;
                            } else if (info instanceof android.content.pm.ApplicationInfo) {
                                pkgName = ((android.content.pm.ApplicationInfo) info).packageName;
                            }
                            
                            if (pkgName != null && (pkgName.contains("magisk") || pkgName.contains("xposed") || 
                                pkgName.contains("edxposed") || pkgName.contains("lsposed") || 
                                pkgName.contains("riru") || pkgName.contains("zygisk"))) {
                                modified = true;
                                XposedBridge.log("ShekharPAIBypass: [DEFENCE] Hid root package from bulk list: " + pkgName);
                            } else {
                                cleanList.add(info);
                            }
                        }
                        if (modified) {
                            param.setResult(cleanList);
                        }
                    }
                }
            };
            XposedHelpers.findAndHookMethod("android.app.ApplicationPackageManager", lpparam.classLoader, "getInstalledPackages", int.class, packageListHook);
            XposedHelpers.findAndHookMethod("android.app.ApplicationPackageManager", lpparam.classLoader, "getInstalledApplications", int.class, packageListHook);

            // 7. Prevent Runtime.exec() and ProcessBuilder for root strings
            XC_MethodHook shellHook = new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    Object cmd = param.args[0];
                    String cmdStr = "";
                    if (cmd instanceof String) cmdStr = (String) cmd;
                    else if (cmd instanceof String[]) cmdStr = java.util.Arrays.toString((String[]) cmd);

                    if (cmdStr.toLowerCase().contains("su") || cmdStr.toLowerCase().contains("which") || 
                        cmdStr.toLowerCase().contains("magisk") || cmdStr.toLowerCase().contains("busybox")) {
                        XposedBridge.log("ShekharPAIBypass: [DEFENCE] Blocked shell command: " + cmdStr);
                        param.setThrowable(new java.io.IOException("Service not found"));
                    }
                }
            };
            XposedHelpers.findAndHookMethod(Runtime.class, "exec", String.class, shellHook);
            XposedHelpers.findAndHookMethod(Runtime.class, "exec", String[].class, shellHook);
            XposedHelpers.findAndHookMethod(Runtime.class, "exec", String.class, String[].class, shellHook);
            XposedHelpers.findAndHookMethod(Runtime.class, "exec", String[].class, String[].class, shellHook);
            XposedHelpers.findAndHookMethod(ProcessBuilder.class, "start", shellHook);

            // 7. Consolidated Setting & ADB Redirection
            try {
                XC_MethodHook settingsHook = new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        String name = (String) param.args[1];
                        if (name == null) return;
                        if (name.equals("adb_enabled") || name.equals("usb_debugging_enabled") || 
                            name.equals("development_settings_enabled") || name.equals("accessibility_enabled")) {
                            XposedBridge.log("ShekharPAIBypass: [UNIVERSAL] Spoofing setting " + name + " -> 0");
                            param.setResult(0);
                        }
                    }
                };
                
                String[] settingsClasses = {"android.provider.Settings.Global", "android.provider.Settings.Secure", "android.provider.Settings.System"};
                for (String cls : settingsClasses) {
                    try {
                        XposedHelpers.findAndHookMethod(cls, lpparam.classLoader, "getInt", android.content.ContentResolver.class, String.class, settingsHook);
                        XposedHelpers.findAndHookMethod(cls, lpparam.classLoader, "getInt", android.content.ContentResolver.class, String.class, int.class, settingsHook);
                        XposedHelpers.findAndHookMethod(cls, lpparam.classLoader, "getString", android.content.ContentResolver.class, String.class, new XC_MethodHook() {
                            @Override
                            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                                String name = (String) param.args[1];
                                if ("adb_enabled".equals(name)) param.setResult("0");
                            }
                        });
                    } catch (Throwable ignore) {}
                }

                // Hook SystemProperties for adb configs
                XposedHelpers.findAndHookMethod("android.os.SystemProperties", lpparam.classLoader, "get", String.class, new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        String key = (String) param.args[0];
                        if (key != null && (key.contains("adb") || key.contains("debug") || key.contains("secure") || key.contains("tags") || key.contains("build"))) {
                            String val = (String) param.getResult();
                            if (key.equals("ro.debuggable")) param.setResult("0");
                            else if (key.equals("ro.secure")) param.setResult("1");
                            else if (key.equals("ro.build.tags")) param.setResult("release-keys");
                            else if (key.equals("ro.build.type")) param.setResult("user");
                            else if (val != null && val.contains("adb")) param.setResult(val.replace("adb", ""));
                        }
                    }
                });
            } catch (Throwable t) {
                XposedBridge.log("ShekharPAIBypass: [UNIVERSAL] Settings redirection failed: " + t.getMessage());
            }

            // 8. Universal SSL Certificate Unpinning
            try {
                // Trust all certificates
                XC_MethodReplacement trustAll = new XC_MethodReplacement() {
                    @Override
                    protected Object replaceHookedMethod(MethodHookParam param) throws Throwable {
                        return null;
                    }
                };

                // Hook X509TrustManager checkServerTrusted & checkClientTrusted
                Class<?>[] paramTypes = new Class[]{java.security.cert.X509Certificate[].class, String.class};
                XposedHelpers.findAndHookMethod("javax.net.ssl.X509TrustManager", lpparam.classLoader, "checkServerTrusted", paramTypes, trustAll);
                XposedHelpers.findAndHookMethod("javax.net.ssl.X509TrustManager", lpparam.classLoader, "checkClientTrusted", paramTypes, trustAll);

                // Hook HostnameVerifier to always return true
                XposedHelpers.findAndHookMethod("javax.net.ssl.HttpsURLConnection", lpparam.classLoader, "setDefaultHostnameVerifier", "javax.net.ssl.HostnameVerifier", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        param.args[0] = new javax.net.ssl.HostnameVerifier() {
                            @Override
                            public boolean verify(String hostname, javax.net.ssl.SSLSession session) {
                                return true;
                            }
                        };
                    }
                });

                // Override SSLContext getSocketFactory
                XposedHelpers.findAndHookMethod("javax.net.ssl.SSLContext", lpparam.classLoader, "init",
                        javax.net.ssl.KeyManager[].class, javax.net.ssl.TrustManager[].class, java.security.SecureRandom.class, new XC_MethodHook() {
                            @Override
                            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                                param.args[1] = new javax.net.ssl.TrustManager[]{
                                        new javax.net.ssl.X509TrustManager() {
                                            @Override
                                            public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) {}
                                            @Override
                                            public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) {}
                                            @Override
                                            public java.security.cert.X509Certificate[] getAcceptedIssuers() { return new java.security.cert.X509Certificate[0]; }
                                        }
                                };
                            }
                        });

                XposedBridge.log("ShekharPAIBypass: [DEFENCE] SSL Unpinning deployed");
            } catch (Throwable t) {
                XposedBridge.log("ShekharPAIBypass: [DEFENCE] SSL Unpinning failed: " + t.getMessage());
            }

            // 7. Prevent ActivityTaskManager from starting Root/Xposed manager apps to see if they exist
            XC_MethodHook startActivityHook = new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    android.content.Intent intent = (android.content.Intent) param.args[0];
                    if (intent != null && intent.getComponent() != null) {
                        String pkg = intent.getComponent().getPackageName();
                        if (pkg.contains("magisk") || pkg.contains("lsposed") || pkg.contains("kernelsu") || pkg.contains("ksunext") || pkg.contains("hidemyapplist")) {
                            XposedBridge.log("ShekharPAIBypass: [DEFENCE] Blocked startActivity for " + pkg);
                            param.setResult(null); // Pretend it worked or block it gracefully
                        }
                    }
                }
            };
            
            try {
                XposedHelpers.findAndHookMethod(Context.class, "startActivity", android.content.Intent.class, startActivityHook);
                XposedHelpers.findAndHookMethod(Context.class, "startActivity", android.content.Intent.class, android.os.Bundle.class, startActivityHook);
                XposedHelpers.findAndHookMethod(android.app.Activity.class, "startActivity", android.content.Intent.class, startActivityHook);
                XposedHelpers.findAndHookMethod(android.app.Activity.class, "startActivity", android.content.Intent.class, android.os.Bundle.class, startActivityHook);
            } catch (Throwable t) {
                // Ignore hooking errors for specific variants if they don't exist
            }

            // 8. Bypass User Certificate Detections
            try {
                // Hide files in cacerts-added and typical cert paths
                XposedHelpers.findAndHookMethod(java.io.File.class, "exists", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        java.io.File file = (java.io.File) param.thisObject;
                        String path = file.getAbsolutePath();
                        if (path != null && (path.contains("cacerts-added") || path.contains("user/0/cacerts"))) {
                            XposedBridge.log("ShekharPAIBypass: [DEFENCE] Blocked generic cert file check: " + path);
                            param.setResult(false);
                        }
                    }
                });

                // Filter user-installed certificates from KeyStore aliases
                XposedHelpers.findAndHookMethod(java.security.KeyStore.class, "aliases", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        Enumeration<String> aliases = (Enumeration<String>) param.getResult();
                        if (aliases != null) {
                            java.util.Vector<String> safeAliases = new java.util.Vector<>();
                            while (aliases.hasMoreElements()) {
                                String alias = aliases.nextElement();
                                // AndroidCAStore uses "user:" prefix for user-installed certificates
                                if (alias != null && !alias.startsWith("user:")) {
                                    safeAliases.add(alias);
                                } else {
                                    XposedBridge.log("ShekharPAIBypass: [DEFENCE] Hid user certificate alias: " + alias);
                                }
                            }
                            param.setResult(safeAliases.elements());
                        }
                    }
                });
                
                // Pretend the AndroidCAStore has fewer certificates (optional, but some RASP checks size)
                XposedHelpers.findAndHookMethod(java.security.KeyStore.class, "size", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        java.security.KeyStore ks = (java.security.KeyStore) param.thisObject;
                        if ("AndroidCAStore".equals(ks.getType())) {
                            int size = (int) param.getResult();
                            // subtract an arbitrary amount if we want, but returning the true system size is hard without enumerating
                            // usually filtering aliases is enough. We can just catch if they ask.
                        }
                    }
                });

                XposedBridge.log("ShekharPAIBypass: [DEFENCE] User Certificate bypass deployed");
            } catch (Throwable t) {
                XposedBridge.log("ShekharPAIBypass: [DEFENCE] User Cert bypass failed: " + t.getMessage());
            }

            // 9. Bypass Proxy Server Detection
            try {
                // Hook ProxySelector to return NoProxy
                Class<?> proxySelectorClass = XposedHelpers.findClass("java.net.ProxySelector", lpparam.classLoader);
                XposedHelpers.findAndHookMethod(proxySelectorClass, "getDefault", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        XposedBridge.log("ShekharPAIBypass: [DEFENCE] Enforced NoProxy in ProxySelector.getDefault()");
                        // Return a custom one that always returns NO_PROXY
                        param.setResult(new java.net.ProxySelector() {
                            @Override
                            public java.util.List<java.net.Proxy> select(java.net.URI uri) {
                                return java.util.Collections.singletonList(java.net.Proxy.NO_PROXY);
                            }
                            @Override
                            public void connectFailed(java.net.URI uri, java.net.SocketAddress sa, java.io.IOException ioe) {}
                        });
                    }
                });

                // Hide proxy from ConnectivityManager
                XposedHelpers.findAndHookMethod("android.net.ConnectivityManager", lpparam.classLoader, "getProxyForNetwork", "android.net.Network", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        param.setResult(null);
                    }
                });
                XposedHelpers.findAndHookMethod("android.net.ConnectivityManager", lpparam.classLoader, "getDefaultProxy", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        param.setResult(null);
                    }
                });

                // Hide proxy from Settings provider
                XC_MethodHook hideSettingHook = new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        String name = (String) param.args[1];
                        if ("http_proxy".equals(name) || "global_http_proxy_host".equals(name) || "global_http_proxy_port".equals(name)) {
                            XposedBridge.log("ShekharPAIBypass: [DEFENCE] Hid proxy setting: " + name);
                            param.setResult(null);
                        }
                    }
                };
                XposedHelpers.findAndHookMethod("android.provider.Settings.Global", lpparam.classLoader, "getString", android.content.ContentResolver.class, String.class, hideSettingHook);
                XposedHelpers.findAndHookMethod("android.provider.Settings.Secure", lpparam.classLoader, "getString", android.content.ContentResolver.class, String.class, hideSettingHook);
                XposedHelpers.findAndHookMethod("android.provider.Settings.System", lpparam.classLoader, "getString", android.content.ContentResolver.class, String.class, hideSettingHook);

                XposedBridge.log("ShekharPAIBypass: [DEFENCE] Proxy bypass deployed");
            } catch (Throwable t) {
                XposedBridge.log("ShekharPAIBypass: [DEFENCE] Proxy bypass failed: " + t.getMessage());
            }

            // 10. OkHttp CertificatePinner Bypass
            try {
                XC_MethodReplacement trustAll = XC_MethodReplacement.returnConstant(null);
                
                // Attempt to hook common OkHttp versions
                String[] okhttpClasses = {"okhttp3.CertificatePinner", "com.squareup.okhttp.CertificatePinner"};
                for (String cls : okhttpClasses) {
                    try {
                        XposedHelpers.findAndHookMethod(cls, lpparam.classLoader, "check", String.class, java.util.List.class, trustAll);
                        XposedHelpers.findAndHookMethod(cls, lpparam.classLoader, "check", String.class, java.security.cert.Certificate[].class, trustAll);
                        XposedBridge.log("ShekharPAIBypass: [DEFENCE] Hooked check() in " + cls);
                    } catch (Throwable ignore) {}
                }
            } catch (Throwable t) {
                XposedBridge.log("ShekharPAIBypass: [DEFENCE] OkHttp bypass failed: " + t.getMessage());
            }

            // 11. Comprehensive Stealth & Package Hiding
            try {
                final java.util.Set<String> blacklist = new java.util.HashSet<>(java.util.Arrays.asList(
                    "com.sch.pai.bypass", "io.github.lsposed.manager", "org.meowcat.lsposed",
                    "com.topjohnwu.magisk", "com.google.android.apps.authenticator2",
                    "com.frida.server", "re.frida.server", "bin.mt.plus", "dialog.box",
                    "com.studio.duckdetector", "org.frknkrc44.hma_oss", "top.ltfan.notdeveloper",
                    "com.network.proxy", "com.resukisu.resukisu", "com.smartpack.packagemanager",
                    "tech.httptoolkit.pinning_demo", "com.jrummyapps.rootchecker",
                    "com.dtm.trustmealready", "com.xposed.disableflagsecure", "com.github.longdt.novpndetect"
                ));

                XC_MethodHook hidePackageHook = new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        Object result = param.getResult();
                        if (result instanceof java.util.List) {
                            java.util.List list = (java.util.List) result;
                            java.util.Iterator it = list.iterator();
                            while (it.hasNext()) {
                                Object item = it.next();
                                String pkgName = null;
                                if (item instanceof android.content.pm.PackageInfo) pkgName = ((android.content.pm.PackageInfo)item).packageName;
                                else if (item instanceof android.content.pm.ApplicationInfo) pkgName = ((android.content.pm.ApplicationInfo)item).packageName;
                                else if (item instanceof android.content.pm.ResolveInfo) {
                                    if (((android.content.pm.ResolveInfo)item).activityInfo != null) pkgName = ((android.content.pm.ResolveInfo)item).activityInfo.packageName;
                                }
                                
                                if (pkgName != null) {
                                    for (String black : blacklist) {
                                        if (pkgName.toLowerCase().contains(black)) {
                                            XposedBridge.log("ShekharPAIBypass: [STEALTH] Hiding blacklisted package: " + pkgName);
                                            it.remove();
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                };

                XposedHelpers.findAndHookMethod("android.app.ApplicationPackageManager", lpparam.classLoader, "getInstalledPackages", int.class, hidePackageHook);
                XposedHelpers.findAndHookMethod("android.app.ApplicationPackageManager", lpparam.classLoader, "getInstalledApplications", int.class, hidePackageHook);
                XposedHelpers.findAndHookMethod("android.app.ApplicationPackageManager", lpparam.classLoader, "queryIntentActivities", android.content.Intent.class, int.class, hidePackageHook);

                // Hide actual files
                XposedHelpers.findAndHookMethod(java.io.File.class, "exists", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        java.io.File file = (java.io.File) param.thisObject;
                        String path = file.getAbsolutePath();
                        if (path != null) {
                            String lower = path.toLowerCase();
                            if (lower.contains("su") || lower.contains("magisk") || lower.contains("frida") || lower.contains("busybox")) {
                                param.setResult(false);
                            }
                        }
                    }
                });

                // Scrub /proc/self/maps and mounts to hide memory/mount traces
                XC_MethodHook procScrubHook = new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        String line = (String) param.getResult();
                        if (line != null) {
                            String lower = line.toLowerCase();
                            if (lower.contains("xposed") || lower.contains("frida") || lower.contains("lsposed") || lower.contains("magisk") || lower.contains("zygisk")) {
                                param.setResult(null);
                            }
                        }
                    }
                };
                XposedHelpers.findAndHookMethod("java.io.BufferedReader", lpparam.classLoader, "readLine", procScrubHook);

                // Hide bypass from RunningAppProcesses
                XposedHelpers.findAndHookMethod("android.app.ActivityManager", lpparam.classLoader, "getRunningAppProcesses", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        java.util.List<android.app.ActivityManager.RunningAppProcessInfo> processes = (java.util.List) param.getResult();
                        if (processes != null) {
                            java.util.Iterator it = processes.iterator();
                            while (it.hasNext()) {
                                android.app.ActivityManager.RunningAppProcessInfo info = (android.app.ActivityManager.RunningAppProcessInfo) it.next();
                                if (info.processName.contains("sch.pai.bypass") || info.processName.contains("frida") || info.processName.contains("lsposed")) {
                                    it.remove();
                                }
                            }
                        }
                    }
                });

                // Hide bypass process from permissions
                XposedHelpers.findAndHookMethod("android.app.ContextImpl", lpparam.classLoader, "checkPermission", String.class, int.class, int.class, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        String permission = (String) param.args[0];
                        if (permission != null && (permission.contains("INSTALL_PACKAGES") || permission.contains("DELETE_PACKAGES"))) {
                            // Some apps check if we have installer permissions to detect side-loading
                        }
                    }
                });
                
                String[] pmClasses = {"android.app.ApplicationPackageManager", "android.content.pm.PackageManager"};
                for (String cls : pmClasses) {
                    try {
                        XposedHelpers.findAndHookMethod(cls, lpparam.classLoader, "checkPermission", String.class, String.class, new XC_MethodHook() {
                            @Override
                            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                                String pkg = (String) param.args[1];
                                if (blacklist.contains(pkg)) {
                                    param.setResult(android.content.pm.PackageManager.PERMISSION_DENIED);
                                }
                            }
                        });
                    } catch (Throwable ignore) {}
                }

                XposedBridge.log("ShekharPAIBypass: [STEALTH] Advanced stealth features deployed");
            } catch (Throwable t) {
                XposedBridge.log("ShekharPAIBypass: [STEALTH] Stealth features failed: " + t.getMessage());
            }

            XposedBridge.log("ShekharPAIBypass: Defensive hooks deployed for " + lpparam.packageName);
        } catch (Throwable t) {
            XposedBridge.log("ShekharPAIBypass: Failed to deploy defensive hooks: " + t.getMessage());
        }
    }

    private void runUniversalScanner(String packageName, String sourceDir, ClassLoader classLoader) {
        XposedBridge.log("ShekharPAIBypass: Starting Universal Heuristic Scan for " + packageName);

        try {
            DexFile dexFile = new DexFile(sourceDir);
            Enumeration<String> entries = dexFile.entries();

            int matchesFound = 0;
            while (entries.hasMoreElements()) {
                String className = entries.nextElement();
                
                // Aggressive skip for common large libraries
                if (className.startsWith("android.") || className.startsWith("androidx.") || 
                    className.startsWith("com.google.") || className.startsWith("java.") || 
                    className.startsWith("kotlin.") || className.startsWith("com.facebook.") ||
                    className.startsWith("okhttp3.") || className.startsWith("com.google.android.gms") ||
                    className.startsWith("com.clevertap.") || className.startsWith("com.netcore.")) continue;

                Class<?> clazz = XposedHelpers.findClassIfExists(className, classLoader);
                if (clazz == null) continue;

                int classScore = calculateClassScore(clazz);
                if (classScore < 10) continue;

                for (Method m : clazz.getDeclaredMethods()) {
                    int methodScore = calculateMethodScore(m, classScore);
                    if (methodScore >= 20) {
                        hookSecurityMethod(m);
                        matchesFound++;
                    }
                }
            }
            XposedBridge.log("ShekharPAIBypass: Signatureless scan complete. Neutralized " + matchesFound + " targets.");
        } catch (Throwable t) {
            XposedBridge.log("ShekharPAIBypass: Scanner failed: " + t.getMessage());
        }
    }

    private int calculateClassScore(Class<?> clazz) {
        String name = clazz.getName().toLowerCase();
        int score = 0;
        
        // Package-based scoring
        if (name.contains("protectt") || name.contains("nsdl") || name.contains("guard") || 
            name.contains("security") || name.contains("rasp") || name.contains("interactor") ||
            name.contains("integrity") || name.contains("safety") || name.contains("tamper") ||
            name.contains("trust") || name.contains("verify") || name.contains("shield")) {
            score += 20;
        }

        // Structural scoring (e.g., obfuscated classes with many booleans)
        if (clazz.getSimpleName().length() <= 2) {
            int boolMethods = 0;
            for (Method m : clazz.getDeclaredMethods()) {
                if (m.getReturnType().equals(boolean.class)) boolMethods++;
            }
            if (boolMethods > 5) score += 15;
        }

        return score;
    }

    private int calculateMethodScore(Method m, int classScore) {
        String name = m.getName().toLowerCase();
        int score = classScore;
        Class<?>[] params = m.getParameterTypes();

        // 1. Semantic Match
        if (name.contains("rooted") || name.contains("hook") || name.contains("xposed") || 
            name.contains("detect") || name.contains("check") || name.contains("emulator") || 
            name.contains("proxy") || name.contains("developer") || name.contains("adb") || 
            name.contains("magisk") || name.contains("zygisk") || name.contains("jailbreak") ||
            name.contains("integrity") || name.contains("safety") || name.contains("tamper") ||
            name.contains("debug") || name.contains("virtual") || name.contains("sandbox") ||
            name.contains("overlay") || name.contains("accessibility") || name.contains("automation") ||
            name.contains("mock") || name.contains("gps") || name.contains("vpn")) {
            score += 15;
        }

        // 2. Init/Starter Match
        for (Class<?>[] sig : RASP_INIT_SIGNATURES) {
            if (params.length == sig.length) {
                boolean match = true;
                for (int i = 0; i < params.length; i++) {
                    if (!params[i].equals(sig[i])) { match = false; break; }
                }
                if (match) {
                    if (m.getReturnType() == void.class || m.getReturnType() == boolean.class) {
                        score += 20;
                    }
                }
            }
        }

        // 3. Generic Check Match (boolean, 0 params)
        if (m.getReturnType().equals(boolean.class) && params.length == 0) {
            score += 5;
        }

        return score;
    }

    private void hookSecurityMethod(final Method m) {
        try {
            XposedBridge.hookMethod(m, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    String name = m.getName().toLowerCase();
                    Class<?> retType = m.getReturnType();

                    // Semantic Return Forgery
                    if (retType.equals(boolean.class)) {
                        // If it sounds like a threat check, return false (not found)
                        if (name.contains("root") || name.contains("hook") || name.contains("xposed") || 
                            name.contains("detect") || name.contains("check") || name.contains("emulator") || 
                            name.contains("proxy") || name.contains("adb") || name.contains("dev")) {
                            param.setResult(false);
                        } 
                        // If it sounds like a safety/init check, return true (is safe)
                        else if (name.contains("safe") || name.contains("valid") || name.contains("success") || name.contains("authorized")) {
                            param.setResult(true);
                        } else {
                            param.setResult(false); // Default to safe/not-found
                        }
                    } else if (retType.equals(void.class)) {
                        param.setResult(null); // Force success/ignore for inits/voids
                    } else if (retType.equals(int.class)) {
                        param.setResult(0); // Often 0 = success in RASP codes
                    } else {
                        // For non-primitives (String, Object, array), DO NOT return null unless we have very high confidence it's a threat list!
                        if (name.contains("detect") || name.contains("threat") || name.contains("risk")) {
                            if (retType.equals(String.class)) param.setResult("");
                            else param.setResult(null);
                        }
                        // Default: We let the original method execute! Breaking Crypto or SharedPreferences is much worse.
                    }
                    
                    // Internal result used for short-circuiting
                }
            });
        } catch (Throwable t) {
            // Ignore hook errors
        }
    }

    private XC_MethodHook getCallback() {
        return new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                try {
                    Method method = (Method) param.method;
                    Class<?> returnType = method.getReturnType();

                    String className = (param.thisObject != null) ?
                            param.thisObject.getClass().getName() :
                            method.getDeclaringClass().getName() + " [Static]";

                    XposedBridge.log("ShekharPAIBypass: Triggered Universal Bypass on " + method.getName() + 
                            " in " + className + " (RT: " + returnType.getSimpleName() + ")");

                    if (returnType.equals(Void.TYPE)) return;

                    if (returnType.isPrimitive()) {
                        if (returnType.equals(boolean.class)) {
                            param.setResult(true);
                        } else if (returnType.equals(int.class) || returnType.equals(byte.class) ||
                                returnType.equals(short.class) || returnType.equals(long.class)) {
                            param.setResult(0);
                        } else if (returnType.equals(float.class) || returnType.equals(double.class)) {
                            param.setResult(0.0);
                        } else if (returnType.equals(char.class)) {
                            param.setResult('\0');
                        }
                    } else {
                        param.setResult(null);
                    }
                } catch (Throwable t) {
                    XposedBridge.log("ShekharPAIBypass: Callback error: " + t.getMessage());
                }
            }
        };
    }
}