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
    
    // The "Digital Fingerprint" of Protectt.ai RASP SDK initialization
    private static final Class<?>[][] RASP_SIGNATURES = {
        // Standard: (String, int, int, int, String, int)
        {String.class, int.class, int.class, int.class, String.class, int.class},
        // Variant: (Context, String, int, int, int, String, int)
        {Context.class, String.class, int.class, int.class, int.class, String.class, int.class}
    };

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {
        // Run defensive hooks immediately to hide LSPosed
        runDefensiveHooks(lpparam);

        XposedBridge.log("ShekharPAIBypass: Loaded for " + lpparam.packageName);

        try {
            XposedHelpers.findAndHookMethod(Application.class, "onCreate", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    try {
                        Context context = (Context) param.thisObject;
                        XposedBridge.log("ShekharPAIBypass: Starting Universal Heuristic Scan for " + context.getPackageName());
                        
                        // We run this in a thread to avoid blocking the UI thread too long, 
                        // though we want it to finish quickly.
                        new Thread(() -> {
                            try {
                                runUniversalScanner(context);
                            } catch (Throwable t) {
                                XposedBridge.log("ShekharPAIBypass: Scanner thread error: " + t.getMessage());
                            }
                        }).start();
                        
                    } catch (Throwable t) {
                        XposedBridge.log("ShekharPAIBypass: Error in onCreate hook: " + t.getMessage());
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

            // 7. ADB Detection Bypass
            try {
                XC_MethodHook adbHook = new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        String name = (String) param.args[1];
                        if ("adb_enabled".equals(name) || "usb_debugging_enabled".equals(name) || "development_settings_enabled".equals(name)) {
                            XposedBridge.log("ShekharPAIBypass: [ADB] Spoofing setting " + name + " to 0");
                            param.setResult(0);
                        }
                    }
                };
                
                String[] settingsClasses = {"android.provider.Settings.Global", "android.provider.Settings.Secure"};
                for (String cls : settingsClasses) {
                    try {
                        XposedHelpers.findAndHookMethod(cls, lpparam.classLoader, "getInt", android.content.ContentResolver.class, String.class, adbHook);
                        XposedHelpers.findAndHookMethod(cls, lpparam.classLoader, "getInt", android.content.ContentResolver.class, String.class, int.class, adbHook);
                    } catch (Throwable ignore) {}
                }

                // Hook SystemProperties for adb configs
                Class<?> sysPropClass = XposedHelpers.findClass("android.os.SystemProperties", lpparam.classLoader);
                XposedHelpers.findAndHookMethod(sysPropClass, "get", String.class, new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        String key = (String) param.args[0];
                        if (key != null && (key.equals("persist.sys.usb.config") || key.equals("sys.usb.config") || key.equals("ro.debuggable"))) {
                            String val = (String) param.getResult();
                            if (val != null && val.contains("adb")) {
                                XposedBridge.log("ShekharPAIBypass: [ADB] Scrubbing 'adb' from " + key);
                                param.setResult(val.replace("adb", "").replace(",,", ","));
                            } else if (key.equals("ro.debuggable")) {
                                param.setResult("0");
                            }
                        }
                    }
                });

                XposedBridge.log("ShekharPAIBypass: [ADB] ADB bypass hooks deployed");
            } catch (Throwable t) {
                XposedBridge.log("ShekharPAIBypass: [ADB] ADB bypass failed: " + t.getMessage());
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
                        param.setResult(java.net.ProxySelector.getDefault()); // Return system default or NoProxy?
                        // Actually, returning a custom one that always returns NO_PROXY is better
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
                    "com.topjohnwu.magisk", "com.google.android.apps.authenticator2", // sometimes used for root hide
                    "com.frida.server", "re.frida.server", "iamnotadeveloper", "com.dia", "dia"
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

                // Scrub /proc/self/maps to hide memory traces
                XposedHelpers.findAndHookMethod("java.io.BufferedReader", lpparam.classLoader, "readLine", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        String line = (String) param.getResult();
                        if (line != null) {
                            String lower = line.toLowerCase();
                            if (lower.contains("xposed") || lower.contains("frida") || lower.contains("lsposed") || lower.contains("magisk")) {
                                // XposedBridge.log("ShekharPAIBypass: [STEALTH] Scrubbed line from maps: " + line);
                                param.setResult(null); // Return null for such lines
                            }
                        }
                    }
                });

                XposedBridge.log("ShekharPAIBypass: [STEALTH] Advanced stealth features deployed");
            } catch (Throwable t) {
                XposedBridge.log("ShekharPAIBypass: [STEALTH] Stealth features failed: " + t.getMessage());
            }

            XposedBridge.log("ShekharPAIBypass: Defensive hooks deployed for " + lpparam.packageName);
        } catch (Throwable t) {
            XposedBridge.log("ShekharPAIBypass: Failed to deploy defensive hooks: " + t.getMessage());
        }
    }

    private void runUniversalScanner(Context context) {
        try {
            ApplicationInfo ai = context.getApplicationInfo();
            String dexPath = ai.sourceDir;
            DexFile dexFile = new DexFile(dexPath);
            Enumeration<String> entries = dexFile.entries();
            ClassLoader classLoader = context.getClassLoader();

            int matchesFound = 0;
            while (entries.hasMoreElements()) {
                String className = entries.nextElement();
                
                // Heuristic: RASP SDKs often have short obfuscated names or contain "protectt"
                // We skip android/androidx/google libs to save time, but check others.
                if (className.startsWith("android.") || className.startsWith("androidx.") || 
                    className.startsWith("com.google.") || className.startsWith("java.") || 
                    className.startsWith("kotlin.")) continue;

                Class<?> clazz = XposedHelpers.findClassIfExists(className, classLoader);
                if (clazz == null) continue;

                for (Method m : clazz.getDeclaredMethods()) {
                    if (isRaspSignature(m)) {
                        XposedBridge.hookMethod(m, getCallback());
                        XposedBridge.log("ShekharPAIBypass: [UNIVERSAL MATCH] Hooked " + m.getDeclaringClass().getName() + "." + m.getName());
                        matchesFound++;
                    }
                }
            }
            XposedBridge.log("ShekharPAIBypass: Heuristic scan complete. Found " + matchesFound + " targets.");
        } catch (Throwable t) {
            XposedBridge.log("ShekharPAIBypass: Universal Scanner failed: " + t.getMessage());
        }
    }

    private boolean isRaspSignature(Method m) {
        String methodName = m.getName().toLowerCase();
        String className = m.getDeclaringClass().getName().toLowerCase();
        
        // 1. Hook anything in Protectt.ai packages blindly
        if (className.contains("protectt") || className.contains("nsdl") || className.contains("AppProtecttInteractor")) {
            if (methodName.contains("init") || methodName.contains("start") || methodName.contains("check") || methodName.contains("detect") || methodName.contains("root") || methodName.contains("hook") || methodName.contains("xposed")) {
                return true;
            }
        }

        Class<?>[] params = m.getParameterTypes();
        
        // 2. Check against our known high-entropy RASP signatures
        for (Class<?>[] sig : RASP_SIGNATURES) {
            if (params.length == sig.length) {
                boolean match = true;
                for (int i = 0; i < params.length; i++) {
                    if (!params[i].equals(sig[i])) {
                        match = false;
                        break;
                    }
                }
                if (match) return true;
            }
        }

        // 3. Generic Heuristic: If method takes 3+ params and mostly ints/Strings
        if (params.length >= 3 && params.length <= 15) {
            int intCount = 0;
            int stringCount = 0;
            int contextCount = 0;
            for (Class<?> p : params) {
                if (p.equals(int.class)) intCount++;
                else if (p.equals(String.class)) stringCount++;
                else if (p.equals(Context.class) || p.equals(Application.class)) contextCount++;
            }
            // Protectt.ai init usually has ints and strings, often a context
            if (intCount >= 2 && stringCount >= 1) return true;
            if (contextCount >= 1 && stringCount >= 2) return true;
        }

        return false;
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