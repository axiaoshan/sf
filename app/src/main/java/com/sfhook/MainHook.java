package com.sfhook;

import android.util.Log;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam;

public class MainHook implements IXposedHookLoadPackage {
    private static final String TAG = "SFTokenHook";
    private static final String TARGET_PKG = "com.sf.activity";

    private static volatile boolean md5Hooked = false;
    private static volatile boolean headerMapHooked = false;
    private static volatile boolean deviceHooked = false;
    private static volatile boolean tokenHooked = false;
    private static volatile boolean saltHooked = false;
    private static volatile boolean encryptMd5Hooked = false;
    private static volatile boolean deviceInfoHooked = false;
    private static volatile boolean riskHooked = false;
    private static volatile boolean cfgHooked = false;
    private static volatile boolean saltProbed = false;
    private static ClassLoader kpLoader = null;

    @Override
    public void handleLoadPackage(LoadPackageParam lp) {
        if (!TARGET_PKG.equals(lp.packageName)) return;
        log("========== SFHook loaded, pkg=" + lp.packageName + " ==========");

        hookClassLoader();
        tryDirectHook(lp.classLoader);
        startRetryThread(lp.classLoader);
    }

    private void hookClassLoader() {
        try {
            XC_MethodHook cl = new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object nameObj = param.args.length > 0 ? param.args[0] : null;
                    if (!(nameObj instanceof String)) return;
                    String name = (String) nameObj;
                    if (name == null) return;
                    Object result = param.getResult();
                    if (!(result instanceof Class)) return;
                    Class<?> cls = (Class<?>) result;

                    if ("com.sf.httpRequest.HeaderInterceptor".equals(name)) {
                        if (!md5Hooked || !headerMapHooked || !deviceHooked) {
                            log("[+] HeaderInterceptor 已加载，开始 hook");
                            hookHeaderInterceptor(cls);
                        }
                    } else if ("com.sf.httpRequest.SYTTokenManager".equals(name)) {
                        if (!tokenHooked || !saltHooked) {
                            log("[+] SYTTokenManager 已加载，开始 hook");
                            hookTokenManager(cls);
                        }
                    } else if ("com.sf.keyprovider.KeyProvider".equals(name)) {
                        if (!encryptMd5Hooked || !deviceInfoHooked || !riskHooked) {
                            log("[+] KeyProvider 已加载，开始 hook");
                            hookKeyProvider(cls);
                        }
                    } else if ("com.sf.keyprovider.generatedconfig.SfGeneratedConfig".equals(name)) {
                        if (!cfgHooked) {
                            log("[+] SfGeneratedConfig 已加载，开始 hook（盐配置读取）");
                            hookSfGeneratedConfig(cls);
                        }
                    }
                }
            };
            XposedBridge.hookAllMethods(ClassLoader.class, "loadClass", cl);
            log("[+] 已挂载 ClassLoader.loadClass 监听");
        } catch (Throwable t) {
            log("[-] hook ClassLoader.loadClass FAILED: " + t);
        }
    }

    private void tryDirectHook(ClassLoader cl) {
        try { hookHeaderInterceptor(XposedHelpers.findClass("com.sf.httpRequest.HeaderInterceptor", cl)); }
        catch (Throwable t) { }
        try { hookTokenManager(XposedHelpers.findClass("com.sf.httpRequest.SYTTokenManager", cl)); }
        catch (Throwable t) { }
        try { hookKeyProvider(XposedHelpers.findClass("com.sf.keyprovider.KeyProvider", cl)); }
        catch (Throwable t) { }
        try { hookSfGeneratedConfig(XposedHelpers.findClass("com.sf.keyprovider.generatedconfig.SfGeneratedConfig", cl)); }
        catch (Throwable t) { }
    }

    private void startRetryThread(final ClassLoader cl) {
        Thread t = new Thread(new Runnable() {
            @Override public void run() {
                for (int i = 0; i < 60; i++) {
                    if (md5Hooked && tokenHooked && encryptMd5Hooked && cfgHooked) break;
                    try { Thread.sleep(1000); } catch (Throwable e) { }
                    tryDirectHook(cl);
                }
            }
        });
        t.setDaemon(true);
        t.start();
    }

    private void hookHeaderInterceptor(Class<?> cls) {
        if (!md5Hooked) {
            try {
                XposedHelpers.findAndHookMethod(cls, "getSytTokenMd5",
                        String.class, String.class, String.class,
                        new XC_MethodHook() {
                            @Override protected void afterHookedMethod(MethodHookParam p) {
                                log("=== getSytTokenMd5 ===");
                                log("  arg0 = [" + argStr(p.args, 0) + "]");
                                log("  arg1 = [" + argStr(p.args, 1) + "]");
                                log("  arg2 = [" + argStr(p.args, 2) + "]");
                                log("  result = " + p.getResult());
                            }
                        });
                md5Hooked = true;
                log("[+] hooked getSytTokenMd5");
            } catch (Throwable t) { log("[-] hook getSytTokenMd5 FAILED: " + t); }
        }
        if (!headerMapHooked) {
            try {
                XposedHelpers.findAndHookMethod(cls, "generateHeaderMap", String.class,
                        new XC_MethodHook() {
                            @Override protected void afterHookedMethod(MethodHookParam p) {
                                log("=== generateHeaderMap ===");
                                Object r = p.getResult();
                                if (r instanceof Map) {
                                    Map m = (Map) r;
                                    for (Object k : m.keySet()) log("  header[" + k + "] = " + m.get(k));
                                }
                            }
                        });
                headerMapHooked = true;
                log("[+] hooked generateHeaderMap");
            } catch (Throwable t) { }
        }
        if (!deviceHooked) {
            try {
                XposedHelpers.findAndHookMethod(cls, "getDeviceId", new XC_MethodHook() {
                    @Override protected void afterHookedMethod(MethodHookParam p) {
                        log("  [getDeviceId] = " + p.getResult());
                    }
                });
                deviceHooked = true;
            } catch (Throwable t) { }
        }
    }

    private void hookTokenManager(Class<?> cls) {
        if (!tokenHooked) {
            try {
                XposedHelpers.findAndHookMethod(cls, "getToken", new XC_MethodHook() {
                    @Override protected void afterHookedMethod(MethodHookParam p) { log("  [getToken] = " + p.getResult()); }
                });
                tokenHooked = true;
            } catch (Throwable t) { }
        }
        if (!saltHooked) {
            try {
                XposedHelpers.findAndHookMethod(cls, "getSalt", new XC_MethodHook() {
                    @Override protected void afterHookedMethod(MethodHookParam p) { log("  [getSalt] = " + p.getResult()); }
                });
                saltHooked = true;
            } catch (Throwable t) { }
        }
    }

    private void hookKeyProvider(Class<?> cls) {
        kpLoader = cls.getClassLoader();
        if (!encryptMd5Hooked) {
            try {
                XposedHelpers.findAndHookMethod(cls, "encryptMD5", String.class, Map.class,
                        new XC_MethodHook() {
                            @Override protected void afterHookedMethod(MethodHookParam p) {
                                log("=== KeyProvider.encryptMD5 ===");
                                log("  str = [" + argStr(p.args, 0) + "]");
                                Object m = p.args[1];
                                if (m instanceof Map) {
                                    for (Object k : ((Map) m).keySet()) log("  map[" + k + "] = " + ((Map) m).get(k));
                                }
                                log("  result = " + p.getResult());
                                // 第一次命中时，主动探测盐配置
                                if (!saltProbed) probeSaltConfig();
                            }
                        });
                encryptMd5Hooked = true;
                log("[+] hooked KeyProvider.encryptMD5");
            } catch (Throwable t) { log("[-] hook encryptMD5 FAILED: " + t); }
        }
        if (!deviceInfoHooked) {
            try {
                XposedHelpers.findAndHookMethod(cls, "getDeviceInfo", new XC_MethodHook() {
                    @Override protected void afterHookedMethod(MethodHookParam p) {
                        Object r = p.getResult();
                        log("=== KeyProvider.getDeviceInfo ===");
                        if (r instanceof Map) {
                            for (Object k : ((Map) r).keySet()) log("  [" + k + "] = " + ((Map) r).get(k));
                        } else log("  result = " + r);
                    }
                });
                deviceInfoHooked = true;
            } catch (Throwable t) { }
        }
        if (!riskHooked) {
            try {
                XposedHelpers.findAndHookMethod(cls, "encryptRiskContext", String.class, String.class,
                        new XC_MethodHook() {
                            @Override protected void afterHookedMethod(MethodHookParam p) {
                                log("=== KeyProvider.encryptRiskContext ===");
                                log("  arg0 = [" + argStr(p.args, 0) + "]");
                                log("  arg1 = [" + argStr(p.args, 1) + "]");
                                log("  result = " + p.getResult());
                            }
                        });
                riskHooked = true;
            } catch (Throwable t) { }
        }
    }

    /** 关键：SfGeneratedConfig.getStringForKey 能直接读出配置明文（盐） */
    private void hookSfGeneratedConfig(Class<?> cls) {
        if (cfgHooked) return;
        try {
            XposedHelpers.findAndHookMethod(cls, "getStringForKey", String.class,
                    new XC_MethodHook() {
                        @Override protected void afterHookedMethod(MethodHookParam p) {
                            log("[CFG] getStringForKey(" + argStr(p.args, 0) + ") = " + p.getResult());
                        }
                    });
            XposedHelpers.findAndHookMethod(cls, "getDictionaryForKey", String.class,
                    new XC_MethodHook() {
                        @Override protected void afterHookedMethod(MethodHookParam p) {
                            log("[CFG] getDictionaryForKey(" + argStr(p.args, 0) + ") = " + p.getResult());
                        }
                    });
            cfgHooked = true;
            log("[+] hooked SfGeneratedConfig.getStringForKey / getDictionaryForKey");
        } catch (Throwable t) {
            log("[-] hook SfGeneratedConfig FAILED: " + t);
        }
    }

    /** 主动探测盐配置：遍历所有可能的盐 key，读出明文 */
    private void probeSaltConfig() {
        saltProbed = true;
        try {
            Class<?> cfg = XposedHelpers.findClass("com.sf.keyprovider.generatedconfig.SfGeneratedConfig", kpLoader);
            String[] keys = {
                "encryptMD5", "tokenSaltkeys", "bodySaltkeys", "encryptSaltkeys",
                "rsaPrivateKey", "tokenSalt", "bodySalt", "encryptSalt",
                "sytSHA3Salt", "sytHttpEncryption", "saltEncryption", "rsaEncryption",
                "tokenSaltKey", "bodySaltKey", "encryptSaltKey"
            };
            log("===== 开始探测盐配置 =====");
            for (String k : keys) {
                try {
                    Object v = XposedHelpers.callStaticMethod(cfg, "getStringForKey", k);
                    log("[PROBE] getStringForKey(" + k + ") = " + v);
                } catch (Throwable t) {
                    log("[PROBE] getStringForKey(" + k + ") ERR: " + t.getClass().getSimpleName());
                }
            }
            for (String k : keys) {
                try {
                    Object v = XposedHelpers.callStaticMethod(cfg, "getDictionaryForKey", k);
                    log("[PROBE] getDictionaryForKey(" + k + ") = " + v);
                } catch (Throwable t) { }
            }
            log("===== 盐配置探测结束 =====");
        } catch (Throwable t) {
            log("[PROBE] 探测失败: " + t);
        }
    }

    private static String argStr(Object[] args, int i) {
        return (i < args.length && args[i] != null) ? args[i].toString() : "null";
    }

    private static void log(String msg) {
        Log.i(TAG, msg);
        XposedBridge.log(msg);
        try {
            File f = new File("/sdcard/sytToken_hook.txt");
            FileOutputStream fos = new FileOutputStream(f, true);
            fos.write((System.currentTimeMillis() + " " + msg + "\n").getBytes(StandardCharsets.UTF_8));
            fos.close();
        } catch (Throwable e) { }
    }
}
