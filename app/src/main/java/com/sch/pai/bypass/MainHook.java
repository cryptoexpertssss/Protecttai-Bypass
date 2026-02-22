package com.sch.pai.bypass;

import android.app.Application;
import android.content.Context;
import android.content.pm.ApplicationInfo;

import java.lang.reflect.Method;
import java.util.Enumeration;

import dalvik.system.DexFile;
import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
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

                try {
                    Class<?> clazz = XposedHelpers.findClassIfExists(className, classLoader);
                    if (clazz == null) continue;

                    for (Method m : clazz.getDeclaredMethods()) {
                        if (isRaspSignature(m)) {
                            XposedBridge.hookMethod(m, getCallback());
                            XposedBridge.log("ShekharPAIBypass: [UNIVERSAL MATCH] Hooked " + m.toString());
                            matchesFound++;
                        }
                    }
                } catch (Throwable ignored) {}
            }
            XposedBridge.log("ShekharPAIBypass: Heuristic scan complete. Found " + matchesFound + " targets.");
        } catch (Throwable t) {
            XposedBridge.log("ShekharPAIBypass: Universal Scanner failed: " + t.getMessage());
        }
    }

    private boolean isRaspSignature(Method m) {
        Class<?>[] params = m.getParameterTypes();
        
        // Check against our known high-entropy RASP signatures
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

        // Generic Heuristic: If method takes 5+ params and mostly ints/Strings
        if (params.length >= 5 && params.length <= 10) {
            int intCount = 0;
            int stringCount = 0;
            for (Class<?> p : params) {
                if (p.equals(int.class)) intCount++;
                else if (p.equals(String.class)) stringCount++;
            }
            // Protectt.ai init usually has 4+ ints and 1-2 strings
            return intCount >= 4 && stringCount >= 1;
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
