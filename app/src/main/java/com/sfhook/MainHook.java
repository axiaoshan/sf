package com.sfhook;

import android.util.Log;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class MainHook implements IXposedHookLoadPackage {
    private static final String TAG = "SFTokenHook";
    private static final String TARGET_PKG = "com.sf.activity";

    @Override
    public void handleLoadPackage(LoadPackageParam lpparam) {
        if (!TARGET_PKG.equals(lpparam.packageName)) return;
        log("========== SFHook loaded, pkg=" + lpparam.packageName + " ==========");

        // 1. hook getSytTokenMd5(String,String,String) —— 核心
        try {
            Class<?> cls = XposedHelpers.findClass("com.sf.httpRequest.HeaderInterceptor", lpparam.classLoader);
            XposedHelpers.findAndHookMethod(cls, "getSytTokenMd5",
                    String.class, String.class, String.class,
                    new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            String a = argStr(param.args, 0);
                            String b = argStr(param.args, 1);
                            String c = argStr(param.args, 2);
                            String result = param.getResult() == null ? "null" : param.getResult().toString();
                            log("=== getSytTokenMd5 ===");
                            log("  arg0 = [" + a + "]");
                            log("  arg1 = [" + b + "]");
                            log("  arg2 = [" + c + "]");
                            log("  result = " + result);
                            // 自动尝试各种拼接，找出 MD5 匹配
                            String match = bruteMd5(result, a, b, c);
                            log("  >>> 拼接匹配: " + (match == null ? "未找到" : match));
                        }
                    });
            log("[+] hooked getSytTokenMd5");
        } catch (Throwable t) {
            log("[-] hook getSytTokenMd5 FAILED: " + t);
        }

        // 2. hook generateHeaderMap —— 看生成的完整头（含 sytToken）
        try {
            Class<?> cls = XposedHelpers.findClass("com.sf.httpRequest.HeaderInterceptor", lpparam.classLoader);
            XposedHelpers.findAndHookMethod(cls, "generateHeaderMap", String.class,
                    new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            log("=== generateHeaderMap ===");
                            log("  arg(url/body) = [" + argStr(param.args, 0) + "]");
                            Object r = param.getResult();
                            if (r instanceof Map) {
                                for (Object k : ((Map) r).keySet()) {
                                    log("  header[" + k + "] = " + ((Map) r).get(k));
                                }
                            } else {
                                log("  result = " + r);
                            }
                        }
                    });
            log("[+] hooked generateHeaderMap");
        } catch (Throwable t) {
            log("[-] hook generateHeaderMap FAILED: " + t);
        }

        // 3. hook SYTTokenManager.getToken / getSalt —— 看缓存种子
        try {
            Class<?> cls = XposedHelpers.findClass("com.sf.httpRequest.SYTTokenManager", lpparam.classLoader);
            XposedHelpers.findAndHookMethod(cls, "getToken", new XC_MethodHook() {
                @Override protected void afterHookedMethod(MethodHookParam p) {
                    log("  [getToken] = " + p.getResult());
                }
            });
            XposedHelpers.findAndHookMethod(cls, "getSalt", new XC_MethodHook() {
                @Override protected void afterHookedMethod(MethodHookParam p) {
                    log("  [getSalt] = " + p.getResult());
                }
            });
            log("[+] hooked SYTTokenManager.getToken/getSalt");
        } catch (Throwable t) {
            log("[-] hook SYTTokenManager FAILED: " + t);
        }

        // 4. hook HeaderInterceptor.getDeviceId
        try {
            Class<?> cls = XposedHelpers.findClass("com.sf.httpRequest.HeaderInterceptor", lpparam.classLoader);
            XposedHelpers.findAndHookMethod(cls, "getDeviceId", new XC_MethodHook() {
                @Override protected void afterHookedMethod(MethodHookParam p) {
                    log("  [getDeviceId] = " + p.getResult());
                }
            });
        } catch (Throwable t) { }
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

    // 自动尝试各种拼接，找出 MD5 匹配（返回拼接表达式）
    private static String bruteMd5(String result, String a, String b, String c) {
        if (result == null || result.length() != 32) return null;
        String[] vals = {a, b, c};
        String[] names = {"a", "b", "c"};
        // 所有排列组合
        List<String[]> candidates = new ArrayList<>();
        // 全排列（3 个全用）
        int[][] perms = {{0,1,2},{0,2,1},{1,0,2},{1,2,0},{2,0,1},{2,1,0}};
        for (int[] p : perms) {
            candidates.add(new String[]{names[p[0]]+names[p[1]]+names[p[2]], vals[p[0]]+vals[p[1]]+vals[p[2]]});
        }
        // 两两
        int[][] pairs = {{0,1},{1,0},{0,2},{2,0},{1,2},{2,1}};
        for (int[] p : pairs) {
            candidates.add(new String[]{names[p[0]]+names[p[1]], vals[p[0]]+vals[p[1]]});
        }
        // 单个
        for (int i = 0; i < 3; i++) {
            candidates.add(new String[]{names[i], vals[i]});
        }
        // 加分隔符的常见组合
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
