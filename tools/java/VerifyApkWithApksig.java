import com.android.apksig.ApkVerifier;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class VerifyApkWithApksig {
    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            throw new IllegalArgumentException("Usage: VerifyApkWithApksig <apk> [minSdk] [maxSdk] [v4SignatureFile]");
        }
        File apk = new File(args[0]);
        ApkVerifier.Builder builder = new ApkVerifier.Builder(apk);
        if (args.length >= 2) {
            builder.setMinCheckedPlatformVersion(Integer.parseInt(args[1]));
        }
        if (args.length >= 3) {
            builder.setMaxCheckedPlatformVersion(Integer.parseInt(args[2]));
        }
        if (args.length >= 4 && !args[3].isEmpty()) {
            builder.setV4SignatureFile(new File(args[3]));
        }

        ApkVerifier.Result result = builder.build().verify();
        List<String> errors = stringify(result.getAllErrors());
        List<String> warnings = stringify(result.getWarnings());
        System.out.println("{");
        System.out.println("  \"verified\": " + result.isVerified() + ",");
        System.out.println("  \"verifiedUsingV1\": " + result.isVerifiedUsingV1Scheme() + ",");
        System.out.println("  \"verifiedUsingV2\": " + result.isVerifiedUsingV2Scheme() + ",");
        System.out.println("  \"verifiedUsingV3\": " + result.isVerifiedUsingV3Scheme() + ",");
        System.out.println("  \"verifiedUsingV31\": " + result.isVerifiedUsingV31Scheme() + ",");
        System.out.println("  \"verifiedUsingV4\": " + result.isVerifiedUsingV4Scheme() + ",");
        System.out.println("  \"signerCertificateCount\": " + result.getSignerCertificates().size() + ",");
        System.out.println("  \"v1SignerCount\": " + result.getV1SchemeSigners().size() + ",");
        System.out.println("  \"v2SignerCount\": " + result.getV2SchemeSigners().size() + ",");
        System.out.println("  \"v3SignerCount\": " + result.getV3SchemeSigners().size() + ",");
        System.out.println("  \"errors\": " + toJsonArray(errors) + ",");
        System.out.println("  \"warnings\": " + toJsonArray(warnings));
        System.out.println("}");
        if (!result.isVerified()) {
            System.exit(2);
        }
    }

    private static List<String> stringify(List<?> issues) {
        List<String> result = new ArrayList<>();
        for (Object issue : issues) {
            result.add(String.valueOf(issue));
        }
        return result;
    }

    private static String toJsonArray(List<String> values) {
        StringBuilder builder = new StringBuilder("[");
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) {
                builder.append(", ");
            }
            builder.append('"').append(escape(values.get(i))).append('"');
        }
        return builder.append(']').toString();
    }

    private static String escape(String value) {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '\\':
                    builder.append("\\\\");
                    break;
                case '"':
                    builder.append("\\\"");
                    break;
                case '\n':
                    builder.append("\\n");
                    break;
                case '\r':
                    builder.append("\\r");
                    break;
                case '\t':
                    builder.append("\\t");
                    break;
                default:
                    builder.append(c);
            }
        }
        return builder.toString();
    }
}
