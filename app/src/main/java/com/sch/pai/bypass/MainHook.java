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
        // LSPosed scope check
        try {
            XposedHelpers.findAndHookMethod(Application.class, "onCreate", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    try {
                        Context context = (Context) param.thisObject;
                        applyUniversalHook(context.getClassLoader());
                    } catch (Throwable ignored) {}
                }
            });
        } catch (Throwable ignored) {}
    }

    private void applyUniversalHook(ClassLoader classLoader) {
        // Expanded targets for Protectt.ai RASP SDK
        String[][] targets = {
                {"f.g", "u1"}, // Kotak Neo
                {"com.protectt.sdk.AppProtecttInteractor", "init"}, // Standard
                {"p0.m", "m1"}, // NSDL Jiffy (Common obfuscation pattern)
                {"a.b", "c"}    // Generic obfuscation
        };

        for (String[] target : targets) {
            try {
                Class<?> clazz = XposedHelpers.findClassIfExists(target[0], classLoader);
                if (clazz == null) continue;

                XposedHelpers.findAndHookMethod(clazz, target[1],
                        String.class, int.class, int.class, int.class, String.class, int.class,
                        new XC_MethodHook() {
                            @Override
                            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                                try {
                                    Method method = (Method) param.method;
                                    Class<?> returnType = method.getReturnType();
                                    XposedBridge.log("ShekharPAIBypass: Hooked " + method.getName() + " in " + target[0] + " (Return: " + returnType.getSimpleName() + ")");

                                    if (returnType.equals(Void.TYPE)) {
                                        return;
                                    }

                                    // COMPREHENSIVE PRIMITIVE HANDLING
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
                                        // For Objects, return null
                                        param.setResult(null);
                                    }
                                } catch (Throwable t) {
                                    XposedBridge.log("ShekharPAIBypass ERROR: " + t.getMessage());
                                }
                            }
                        });
            } catch (Throwable ignored) {}
        }
    }
}
