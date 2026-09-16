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

    @Override
    public void handleLoadPackage(LoadPackageParam lp) {
        if (!TARGET_PKG.equals(lp.packageName)) return;
        log("========== SFHook loaded, pkg=" + lp.packageName + " ==========");

        // 方案A（核心）：监听所有 ClassLoader.loadClass，等娜迦壳解密加载出目标类时再 hook
        hookClassLoader();

        // 方案B：立即尝试（若类已加载/无加固，直接命中）
        tryDirectHook(lp.classLoader);

        // 方案C：后台轮询兜底（最多 60 秒）
        startRetryThread(lp.classLoader);
    }

    /** 监听类加载 —— 加固兼容的关键。娜迦的业务类在运行时解密后由自定义 ClassLoader 加载。 */
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
                    }
                }
            };
            XposedBridge.hookAllMethods(ClassLoader.class, "loadClass", cl);
            log("[+] 已挂载 ClassLoader.loadClass 监听");
        } catch (Throwable t) {
            log("[-] hook ClassLoader.loadClass FAILED: " + t);
        }
    }

    /** 立即尝试（类可能已在默认 ClassLoader 中） */
    private void tryDirectHook(ClassLoader cl) {
        try {
            Class<?> cls = XposedHelpers.findClass("com.sf.httpRequest.HeaderInterceptor", cl);
            hookHeaderInterceptor(cls);
        } catch (Throwable t) {
            log("[-] 直接 findClass HeaderInterceptor 未命中（加固类延迟加载，属正常）: " + t.getClass().getSimpleName());
        }
        try {
            Class<?> cls = XposedHelpers.findClass("com.sf.httpRequest.SYTTokenManager", cl);
            hookTokenManager(cls);
        } catch (Throwable t) { }
    }

    /** 后台轮询兜底 */
    private void startRetryThread(final ClassLoader cl) {
        Thread t = new Thread(new Runnable() {
            @Override public void run() {
                for (int i = 0; i < 60; i++) {
                    if (md5Hooked && tokenHooked) break;
                    try { Thread.sleep(1000); } catch (Throwable e) { }
                    if (!md5Hooked || !tokenHooked) {
                        tryDirectHook(cl);
                    }
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
                                String a = argStr(p.args, 0);
                                String b = argStr(p.args, 1);
                                String c = argStr(p.args, 2);
                                String result = p.getResult() == null ? "null" : p.getResult().toString();
                                log("=== getSytTokenMd5 ===");
                                log("  arg0 = [" + a + "]");
                                log("  arg1 = [" + b + "]");
                                log("  arg2 = [" + c + "]");
                                log("  result = " + result);
                                String match = bruteMd5(result, a, b, c);
                                log("  >>> 拼接匹配: " + (match == null ? "未找到" : match));
                            }
                        });
                md5Hooked = true;
                log("[+] hooked getSytTokenMd5");
            } catch (Throwable t) {
                log("[-] hook getSytTokenMd5 FAILED: " + t);
            }
        }
        if (!headerMapHooked) {
            try {
                XposedHelpers.findAndHookMethod(cls, "generateHeaderMap", String.class,
                        new XC_MethodHook() {
                            @Override protected void afterHookedMethod(MethodHookParam p) {
                                log("=== generateHeaderMap ===");
                                log("  arg = [" + argStr(p.args, 0) + "]");
                                Object r = p.getResult();
                                if (r instanceof Map) {
                                    Map m = (Map) r;
                                    for (Object k : m.keySet()) log("  header[" + k + "] = " + m.get(k));
                                } else {
                                    log("  result = " + r);
                                }
                            }
                        });
                headerMapHooked = true;
                log("[+] hooked generateHeaderMap");
            } catch (Throwable t) {
                log("[-] hook generateHeaderMap FAILED: " + t);
            }
        }
        if (!deviceHooked) {
            try {
                XposedHelpers.findAndHookMethod(cls, "getDeviceId", new XC_MethodHook() {
                    @Override protected void afterHookedMethod(MethodHookParam p) {
                        log("  [getDeviceId] = " + p.getResult());
                    }
                });
                deviceHooked = true;
                log("[+] hooked getDeviceId");
            } catch (Throwable t) { }
        }
    }

    private void hookTokenManager(Class<?> cls) {
        if (!tokenHooked) {
            try {
                XposedHelpers.findAndHookMethod(cls, "getToken", new XC_MethodHook() {
                    @Override protected void afterHookedMethod(MethodHookParam p) {
                        log("  [getToken] = " + p.getResult());
                    }
                });
                tokenHooked = true;
                log("[+] hooked getToken");
            } catch (Throwable t) {
                log("[-] hook getToken FAILED: " + t);
            }
        }
        if (!saltHooked) {
            try {
                XposedHelpers.findAndHookMethod(cls, "getSalt", new XC_MethodHook() {
                    @Override protected void afterHookedMethod(MethodHookParam p) {
                        log("  [getSalt] = " + p.getResult());
                    }
                });
                saltHooked = true;
                log("[+] hooked getSalt");
            } catch (Throwable t) { }
        }
    }

    private static String argStr(Object[] args, int i) {
        return (i < args.length && args[i] != null) ? args[i].toString() : "null";
    }

    private static String md5hex(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] d = md.digest(s.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : d) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }

    private static String bruteMd5(String result, String a, String b, String c) {
        if (result == null || result.length() != 32) return null;
        String[] vals = {a, b, c};
        String[] names = {"a", "b", "c"};
        List<String[]> candidates = new ArrayList<>();
        int[][] perms = {{0,1,2},{0,2,1},{1,0,2},{1,2,0},{2,0,1},{2,1,0}};
        for (int[] p : perms) {
            candidates.add(new String[]{names[p[0]]+names[p[1]]+names[p[2]], vals[p[0]]+vals[p[1]]+vals[p[2]]});
        }
        int[][] pairs = {{0,1},{1,0},{0,2},{2,0},{1,2},{2,1}};
        for (int[] p : pairs) {
            candidates.add(new String[]{names[p[0]]+names[p[1]], vals[p[0]]+vals[p[1]]});
        }
        for (int i = 0; i < 3; i++) {
            candidates.add(new String[]{names[i], vals[i]});
        }
        String[] seps = {"", "&", "|", "_", "-", ":", ";"};
        for (String sep : seps) {
            for (int[] p : perms) {
                candidates.add(new String[]{names[p[0]]+"+"+sep+"+"+names[p[1]]+"+"+sep+"+"+names[p[2]],
                    vals[p[0]]+sep+vals[p[1]]+sep+vals[p[2]]});
            }
        }
        for (String[] cand : candidates) {
            if (md5hex(cand[1]).equalsIgnoreCase(result)) {
                return "MD5(" + cand[1] + ")  [即 " + cand[0] + "]";
            }
        }
        return null;
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
