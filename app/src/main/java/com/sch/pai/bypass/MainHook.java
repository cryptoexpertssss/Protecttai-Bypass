package com.sch.pai.bypass;

import android.app.Application;
import android.content.Context;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class MainHook implements IXposedHookLoadPackage {
    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {
        try {
            // We hook Application.onCreate to get the right ClassLoader.
            // Using a simple afterHook ensures we don't interfere with app startup.
            XposedHelpers.findAndHookMethod(Application.class, "onCreate", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    try {
                        Context context = (Context) param.thisObject;
                        ClassLoader classLoader = context.getClassLoader();
                        XposedBridge.log("ShekharPAIBypass: Application.onCreate detected for " + context.getPackageName());
                        applyUniversalHook(classLoader);
                    } catch (Throwable t) {
                        XposedBridge.log("ShekharPAIBypass: Critical error in onCreate hook: " + t.getMessage());
                    }
                }
            });
        } catch (Throwable t) {
            // Some apps might use custom contexts or be extremely stripped
            XposedBridge.log("ShekharPAIBypass: Failed to hook Application.onCreate: " + t.getMessage());
        }
    }

    private void applyUniversalHook(ClassLoader classLoader) {
        // Known Protectt.ai RASP SDK init signatures and obfuscated names
        String[][] targets = {
                {"f.g", "u1"}, // Kotak Neo
                {"com.protectt.sdk.AppProtecttInteractor", "init"}, // Standard SDK
                {"p0.m", "m1"}, // NSDL Jiffy pattern
                {"q.r", "s"},   // Generic pattern 1
                {"a.b", "c"}    // Generic pattern 2
        };

        for (String[] target : targets) {
            try {
                // Check if the class exists in the current app
                Class<?> clazz = XposedHelpers.findClassIfExists(target[0], classLoader);
                if (clazz == null) continue;

                XposedBridge.log("ShekharPAIBypass: Target class found: " + target[0]);

                XposedHelpers.findAndHookMethod(clazz, target[1],
                        String.class, int.class, int.class, int.class, String.class, int.class,
                        new XC_MethodHook() {
                            @Override
                            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                                try {
                                    Method method = (Method) param.method;
                                    Class<?> returnType = method.getReturnType();
                                    
                                    // LOGGING FIX: Check for static methods to avoid NPE
                                    String className = (param.thisObject != null) ? 
                                            param.thisObject.getClass().getName() : 
                                            method.getDeclaringClass().getName() + " [Static]";
                                            
                                    XposedBridge.log("ShekharPAIBypass: Hooked " + method.getName() + " in " + 
                                            className + " (RT: " + returnType.getSimpleName() + ")");

                                    if (returnType.equals(Void.TYPE)) return;

                                    // Handle all primitives with safe defaults
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
                        });
            } catch (Throwable t) {
                // Method signature didn't match or other hooking issue
            }
        }
    }
}
