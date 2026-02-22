package com.reveny.protecttai.bypass;

import android.content.Context;
import android.util.Log;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class MainHook implements IXposedHookLoadPackage {
    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {
        // Exclude common system and library packages to save time
        if (lpparam.packageName.startsWith("android.") || 
            lpparam.packageName.startsWith("com.google.") ||
            lpparam.packageName.equals("com.reveny.protecttai.bypass")) {
            return;
        }

        XposedBridge.log("Protectt.ai Bypass: Scanning " + lpparam.packageName);

        // We search for the specific method signature used by Protectt.ai RASP SDK:
        // (String, int, int, int, String, int)
        // In Kotak Neo it was f.g.u1, but it varies by app due to obfuscation.
        
        try {
            // Use DexKit-like approach or simple reflection if classes are already loaded
            // Since we are in handleLoadPackage, we can use lpparam.classLoader
            
            // To be truly universal, we can hook the constructor or a common entry point
            // However, a structural search for the signature is most reliable
            
            // For now, let's look for the known Kotak and NSDL patterns if we have them,
            // but the "generic" way is to scan.
            
            // NOTE: Scanning all classes can be slow. A better way is to hook common SDK entry points.
            // Protectt usually initializes in Application.onCreate
            
            XposedHelpers.findAndHookMethod(android.app.Application.class, "onCreate", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Context context = (Context) param.thisObject;
                    ClassLoader classLoader = context.getClassLoader();
                    
                    // Here we could iterate, but for the first version of "Universal",
                    // let's try the common obfuscated names and the signature search.
                    
                    // Signature: (String, int, int, int, String, int)
                    // We'll hook the method dynamically if found.
                    applyUniversalHook(classLoader);
                }
            });
            
        } catch (Exception e) {
            XposedBridge.log("Protectt.ai Bypass Error: " + e.getMessage());
        }
    }

    private void applyUniversalHook(ClassLoader classLoader) {
        // This is a placeholder for a more advanced scanner.
        // For now, we use the known signature which is very unique to the SDK.
        // In a real "Universal" module, we'd use DexKit to find the method bytecode pattern.
        
        // Let's try to hook the known ones first for reliability
        String[][] targets = {
            {"f.g", "u1"}, // Kotak Neo
            {"com.protectt.sdk.AppProtecttInteractor", "init"} // Potential non-obfuscated
        };

        for (String[] target : targets) {
            try {
                XposedHelpers.findAndHookMethod(target[0], classLoader, target[1], 
                    String.class, int.class, int.class, int.class, String.class, int.class, 
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            XposedBridge.log("Protectt.ai Bypass: Successfully hooked " + param.method.getName());
                            param.setResult(null);
                        }
                    });
            } catch (XposedHelpers.ClassNotFoundError | NoSuchMethodError ignored) {
                // Not the target class/method
            }
        }
    }

}
