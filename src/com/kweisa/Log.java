package com.kweisa;


import org.bouncycastle.util.encoders.Hex;

public class Log {
    public static void d(String tag, String message) {
        System.out.println(tag + ":\t" + message);
    }

    public static void d(String tag, byte[] message) {
        d(tag + " [" + message.length + "]", Hex.toHexString(message));
    }

    public static void d(String tag, boolean message) {
        System.out.println(tag + ":\t" + message);
    }
}
