package com.kami.license;

/** base64url 解码（无填充）。服务端签发与前端传输都用此变体。 */
final class Base64Url {

    private static final char[] ALPHABET =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".toCharArray();
    private static final int[] LOOKUP = new int[128];

    static {
        for (int i = 0; i < LOOKUP.length; i++) {
            LOOKUP[i] = -1;
        }
        for (int i = 0; i < ALPHABET.length; i++) {
            LOOKUP[ALPHABET[i]] = i;
        }
    }

    private Base64Url() {
    }

    static byte[] decode(String s) {
        int len = s.length();
        int pad = len % 4;
        int outLen = len / 4 * 3 + (pad == 2 ? 1 : pad == 3 ? 2 : 0);
        byte[] out = new byte[outLen];
        int buf = 0;
        int bits = 0;
        int pos = 0;
        for (int i = 0; i < len; i++) {
            char c = s.charAt(i);
            if (c == '=') {
                break;
            }
            int v = c < 128 ? LOOKUP[c] : -1;
            if (v < 0) {
                throw new IllegalArgumentException("invalid base64url char: " + c);
            }
            buf = (buf << 6) | v;
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                out[pos++] = (byte) ((buf >>> bits) & 0xff);
            }
        }
        return out;
    }
}
