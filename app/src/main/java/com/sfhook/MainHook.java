package com.sfhook;

import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam;

public class MainHook implements IXposedHookLoadPackage {
    private static final String TAG = "SFTokenHook";
    private static final String TARGET_PKG = "com.sf.activity";
    private static final String CMD_PATH = "/data/data/com.sf.activity/files/syt_cmd.txt";
    private static final String RESULT_PATH = "/data/data/com.sf.activity/files/syt_result.txt";

    private static volatile boolean md5Hooked = false;
    private static volatile boolean encryptMd5Hooked = false;
    private static volatile boolean tokenServiceStarted = false;
    private static volatile int dumpCount = 0;

    private static ClassLoader kpLoader = null;
    private static Class<?> keyProviderClass = null;
    // 首次 hook 时记录的固定 map 值（deviceId/jsbundle/clientVersion/languageCode/regionCode）
    private static final Map<String, String> fixedMap = new HashMap<>();

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
                        if (!md5Hooked) hookHeaderInterceptor(cls);
                    } else if ("com.sf.keyprovider.KeyProvider".equals(name)) {
                        if (!encryptMd5Hooked) hookKeyProvider(cls);
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
        try { hookKeyProvider(XposedHelpers.findClass("com.sf.keyprovider.KeyProvider", cl)); }
        catch (Throwable t) { }
    }

    /** 后台轮询重试：娜迦类延迟加载，每秒 findClass 直到 hook 成功 */
    private void startRetryThread(final ClassLoader cl) {
        Thread t = new Thread(new Runnable() {
            @Override public void run() {
                for (int i = 0; i < 60; i++) {
                    if (md5Hooked && encryptMd5Hooked) break;
                    try { Thread.sleep(1000); } catch (Throwable e) { }
                    tryDirectHook(cl);
                }
            }
        });
        t.setDaemon(true);
        t.start();
    }

    private void hookHeaderInterceptor(Class<?> cls) {
        if (md5Hooked) return;
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
        } catch (Throwable t) {
            log("[-] hook getSytTokenMd5 FAILED: " + t);
        }
    }

    private void hookKeyProvider(Class<?> cls) {
        kpLoader = cls.getClassLoader();
        keyProviderClass = cls;
        if (encryptMd5Hooked) return;
        try {
            XposedHelpers.findAndHookMethod(cls, "encryptMD5", String.class, Map.class,
                    new XC_MethodHook() {
                        @Override protected void afterHookedMethod(MethodHookParam p) {
                            log("=== KeyProvider.encryptMD5 ===");
                            log("  str = [" + argStr(p.args, 0) + "]");
                            Object m = p.args[1];
                            if (m instanceof Map) {
                                for (Object k : ((Map) m).keySet()) {
                                    log("  map[" + k + "] = " + ((Map) m).get(k));
                                }
                            }
                            log("  result = " + p.getResult());
                            // 首次记录固定 map 值（去掉 timeInterval）
                            if (fixedMap.isEmpty() && m instanceof Map) {
                                synchronized (fixedMap) {
                                    for (Object k : ((Map) m).keySet()) {
                                        String ks = k.toString();
                                        if (!"timeInterval".equals(ks) && ((Map) m).get(k) != null) {
                                            fixedMap.put(ks, ((Map) m).get(k).toString());
                                        }
                                    }
                                }
                                log("[TOKEN] 已记录固定 map: " + fixedMap);
                            }
                            // MD5 刚执行完，立即 dump 代码段（抓明文页）
                            if (dumpCount < 3) {
                                dumpCount++;
                                dumpCode("after_md5_" + dumpCount + "_" + System.currentTimeMillis());
                            }
                        }
                    });
            encryptMd5Hooked = true;
            log("[+] hooked KeyProvider.encryptMD5");
            startTokenService();
        } catch (Throwable t) {
            log("[-] hook encryptMD5 FAILED: " + t);
        }
    }

    /** 在 MD5 刚执行完时，dump libKeyProvider.so 代码段（进程内读 /proc/self/mem） */
    private void dumpCode(String tag) {
        try {
            String maps = readFile("/proc/self/maps");
            long start = -1, end = -1;
            for (String line : maps.split("\n")) {
                if (line.contains("libKeyProvider.so") && line.contains("r-xp")) {
                    String[] parts = line.trim().split("\\s+");
                    String[] range = parts[0].split("-");
                    start = Long.parseLong(range[0], 16);
                    end = Long.parseLong(range[1], 16);
                    break;
                }
            }
            if (start < 0) {
                log("[DUMP] 未找到 libKeyProvider.so 代码段");
                return;
            }
            RandomAccessFile mem = new RandomAccessFile("/proc/self/mem", "r");
            mem.seek(start);
            byte[] buf = new byte[(int) (end - start)];
            mem.readFully(buf);
            mem.close();
            String out = "/data/data/com.sf.activity/files/" + tag + ".bin";
            writeFile(out, buf);
            log("[DUMP] 代码段 dump 完成: " + out + " (" + buf.length + " bytes)");
        } catch (Throwable t) {
            log("[DUMP] 失败: " + t.getClass().getSimpleName() + " " + t.getMessage());
        }
    }

    /** 主动生成 token 服务：轮询命令文件，调用 encryptMD5 生成任意 body 的 sytToken */
    private void startTokenService() {
        if (tokenServiceStarted) return;
        tokenServiceStarted = true;
        Thread t = new Thread(new Runnable() {
            @Override public void run() {
                log("[TOKEN] token 生成服务已启动");
                // 等 fixedMap 记录好（encryptMD5 首次 hook 时记录），最多等 15 秒
                for (int i = 0; i < 15 && fixedMap.isEmpty(); i++) {
                    try { Thread.sleep(1000); } catch (Throwable e) { }
                }
                log("[DIFF] 主动执行差分测试（fixedMap=" + (fixedMap.isEmpty() ? "空" : fixedMap) + "）");
                String diff = diffTest();
                writeFile(RESULT_PATH, diff);
                log("[DIFF] 差分测试结果已写入 result 文件");

                String lastCmd = "";
                while (true) {
                    try {
                        Thread.sleep(500);
                        String cmd = readFile(CMD_PATH);
                        if (cmd != null && !cmd.isEmpty() && !cmd.equals(lastCmd)) {
                            lastCmd = cmd;
                            log("[TOKEN] 收到命令: " + cmd);
                            String out;
                            if ("DIFF".equals(cmd.trim())) {
                                out = diffTest();
                                log("[DIFF] 差分测试完成");
                            } else {
                                out = genToken(cmd);
                                log("[TOKEN] 生成 token: " + out);
                            }
                            writeFile(RESULT_PATH, out);
                        }
                    } catch (Throwable e) {
                        log("[TOKEN] 服务异常: " + e);
                    }
                }
            }
        });
        t.setDaemon(true);
        t.start();
    }

    /** 调用 KeyProvider.encryptMD5(body, map) 生成 token，map 用记录的固定值 + 当前时间戳 */
    private String genToken(String body) {
        try {
            if (keyProviderClass == null) return "ERROR: KeyProvider 未加载";
            Map<String, String> map = new HashMap<>();
            synchronized (fixedMap) {
                map.putAll(fixedMap);
            }
            map.put("timeInterval", String.valueOf(System.currentTimeMillis()));
            log("[TOKEN] 构造 map: " + map);
            Object result = XposedHelpers.callStaticMethod(keyProviderClass, "encryptMD5", body, map);
            return result == null ? "null" : result.toString();
        } catch (Throwable t) {
            return "ERROR: " + t.getClass().getSimpleName() + " " + t.getMessage();
        }
    }

    private static String argStr(Object[] args, int i) {
        return (i < args.length && args[i] != null) ? args[i].toString() : "null";
    }

    /** 差分测试：改一个输入看输出变化，确定哪些参数参与 MD5 + 盐的位置 */
    private String diffTest() {
        StringBuilder sb = new StringBuilder();
        try {
            if (keyProviderClass == null) return "ERROR: KeyProvider 未加载";
            String body0 = "{\"memberId\":\"\"}";
            Map<String, String> map0 = new HashMap<>();
            synchronized (fixedMap) { map0.putAll(fixedMap); }
            map0.put("timeInterval", "1789559580000");  // 固定时间戳，排除时间干扰

            sb.append("基线        body0+map0     = ").append(call(body0, map0)).append("\n");
            sb.append("重复        body0+map0     = ").append(call(body0, map0)).append("\n");
            sb.append("空body      ''+map0        = ").append(call("", map0)).append("\n");
            sb.append("body=a      a+map0         = ").append(call("a", map0)).append("\n");
            sb.append("body=ab     ab+map0        = ").append(call("ab", map0)).append("\n");
            sb.append("body=abc    abc+map0       = ").append(call("abc", map0)).append("\n");

            Map m = new HashMap<>(map0); m.put("timeInterval", "0");
            sb.append("ts=0        body0+ts0      = ").append(call(body0, m)).append("\n");
            m = new HashMap<>(map0); m.put("timeInterval", "1");
            sb.append("ts=1        body0+ts1      = ").append(call(body0, m)).append("\n");
            m = new HashMap<>(map0); m.put("deviceId", "x");
            sb.append("deviceId=x  body0+did=x    = ").append(call(body0, m)).append("\n");
            m = new HashMap<>(map0); m.put("jsbundle", "y");
            sb.append("jsbundle=y  body0+js=y     = ").append(call(body0, m)).append("\n");
            m = new HashMap<>(map0); m.put("regionCode", "z");
            sb.append("region=z    body0+rc=z     = ").append(call(body0, m)).append("\n");
            m = new HashMap<>(map0); m.put("languageCode", "w");
            sb.append("lang=w      body0+lc=w     = ").append(call(body0, m)).append("\n");
            m = new HashMap<>(map0); m.put("clientVersion", "v");
            sb.append("clientVer=v body0+cv=v     = ").append(call(body0, m)).append("\n");

            Map empty = new HashMap<>();
            sb.append("空map       body0+{}       = ").append(call(body0, empty)).append("\n");
        } catch (Throwable t) {
            sb.append("DIFF ERROR: ").append(t).append("\n");
        }
        return sb.toString();
    }

    private String call(String body, Map<String, String> map) {
        try {
            Object r = XposedHelpers.callStaticMethod(keyProviderClass, "encryptMD5", body, map);
            return r == null ? "null" : r.toString();
        } catch (Throwable t) {
            return "ERR:" + t.getClass().getSimpleName();
        }
    }

    private static String readFile(String path) {
        try {
            File f = new File(path);
            if (!f.exists()) return "";
            FileInputStream fis = new FileInputStream(f);
            BufferedReader br = new BufferedReader(new InputStreamReader(fis, StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) sb.append(line).append("\n");
            br.close();
            return sb.toString().trim();
        } catch (Throwable e) {
            return "";
        }
    }

    private static void writeFile(String path, String content) {
        try {
            File f = new File(path);
            if (f.getParentFile() != null) f.getParentFile().mkdirs();
            FileOutputStream fos = new FileOutputStream(f);
            fos.write(content.getBytes(StandardCharsets.UTF_8));
            fos.close();
        } catch (Throwable e) { }
    }

    private static void writeFile(String path, byte[] content) {
        try {
            File f = new File(path);
            if (f.getParentFile() != null) f.getParentFile().mkdirs();
            FileOutputStream fos = new FileOutputStream(f);
            fos.write(content);
            fos.close();
        } catch (Throwable e) { }
    }

    private static void log(String msg) {
        Log.i(TAG, msg);
        XposedBridge.log(msg);
        String[] paths = {
            "/data/data/com.sf.activity/files/sytToken_hook.txt",
            "/sdcard/Download/sytToken_hook.txt",
            "/sdcard/sytToken_hook.txt",
        };
        for (String p : paths) {
            try {
                File f = new File(p);
                if (f.getParentFile() != null) f.getParentFile().mkdirs();
                FileOutputStream fos = new FileOutputStream(f, true);
                fos.write((System.currentTimeMillis() + " " + msg + "\n").getBytes(StandardCharsets.UTF_8));
                fos.close();
                break;
            } catch (Throwable e) { }
        }
    }
}
