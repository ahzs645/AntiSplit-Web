package android.text;

public class TextUtils {
    public static boolean isEmpty(CharSequence value) {
        return value == null || value.length() == 0;
    }
}
