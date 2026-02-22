package com.sch.pai.bypass;

import android.app.Application;
import android.content.Context;

import java.lang.reflect.Method;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class MainHook implements IXposedHookLoadPackage {
    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {
        // LSPosed handles the scope. We only process apps selected by the user.
        // We avoid logging here to prevent cluttering the Xposed log.

        try {
            // Hook Application.onCreate to get the ClassLoader in a stable way
            XposedHelpers.findAndHookMethod(Application.class, "onCreate", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    try {
                        Context context = (Context) param.thisObject;
                        ClassLoader classLoader = context.getClassLoader();
                        applyUniversalHook(classLoader);
                    } catch (Throwable t) {
                        // Silently catch to prevent host app crash
                    }
                }
            });
        } catch (Throwable t) {
            // Application.onCreate hook failed (shouldn't happen, but safety first)
        }
    }

    private void applyUniversalHook(ClassLoader classLoader) {
        // Patterns for Protectt.ai RASP SDK
        // (String, int, int, int, String, int)
        String[][] targets = {
                {"f.g", "u1"}, // Kotak Neo (obfuscated)
                {"com.protectt.sdk.AppProtecttInteractor", "init"} // Standard SDK entry
        };

        for (String[] target : targets) {
            try {
                // Check if class exists before attempting to hook to avoid internal Xposed noise
                Class<?> clazz = XposedHelpers.findClassIfExists(target[0], classLoader);
                if (clazz == null) continue;

                XposedHelpers.findAndHookMethod(clazz, target[1],
                        String.class, int.class, int.class, int.class, String.class, int.class,
                        new XC_MethodHook() {
                            @Override
                            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                                try {
                                    XposedBridge.log("ShekharPAIBypass: Hooked " + param.method.getName() + " in " + param.thisObject.getClass().getName());
                                    
                                    // SAFELY handle return values to prevent NPE/Crashes
                                    // If the method returns an Object (like the known null-return bypasses)
                                    // We check the return type of the method.
                                    Method method = (Method) param.method;
                                    Class<?> returnType = method.getReturnType();

                                    if (returnType.equals(Void.TYPE)) {
                                        // Method returns void, just continue after potentially logging
                                        return;
                                    } else if (returnType.isPrimitive()) {
                                        // For primitives, return a safe "success" value
                                        if (returnType.equals(boolean.class)) {
                                            param.setResult(true); // Usually true for 'initialized' or 'safe'
                                        } else if (returnType.equals(int.class)) {
                                            param.setResult(0); // 0 is common for success codes
                                        }
                                    } else {
                                        // For Objects, return null as per the known Protectt.ai bypass pattern
                                        param.setResult(null);
                                    }
                                } catch (Throwable t) {
                                    XposedBridge.log("ShekharPAIBypass: Callback error: " + t.getMessage());
                                }
                            }
                        });
            } catch (Throwable ignored) {
                // Not the target class/method or hook failed
            }
        }
    }
}
