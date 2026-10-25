// Prints an APK's signing facts as JSON, using Google's own verifier (com.android.apksig, the code
// behind `apksigner verify`). Run: java -cp apksig-9.3.3.jar ApkSigCheck.java app.apk
import com.android.apksig.ApkVerifier;
import java.io.File;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;

public class ApkSigCheck {
    public static void main(String[] args) throws Exception {
        StringBuilder out = new StringBuilder("{");
        try {
            ApkVerifier.Result r = new ApkVerifier.Builder(new File(args[0])).build().verify();
            out.append("\"verified\":").append(r.isVerified());
            out.append(",\"v1\":").append(r.isVerifiedUsingV1Scheme());
            out.append(",\"v2\":").append(r.isVerifiedUsingV2Scheme());
            out.append(",\"v3\":").append(r.isVerifiedUsingV3Scheme());
            out.append(",\"v31\":").append(r.isVerifiedUsingV31Scheme());
            out.append(",\"v4\":").append(r.isVerifiedUsingV4Scheme());
            out.append(",\"errors\":").append(strings(r.getAllErrors()));
            out.append(",\"signers\":[");
            String sep = "";
            for (X509Certificate c : r.getSignerCertificates()) {
                out.append(sep).append("{");
                out.append("\"subject\":").append(q(c.getSubjectX500Principal().getName()));
                out.append(",\"issuer\":").append(q(c.getIssuerX500Principal().getName()));
                out.append(",\"signature_algorithm\":").append(q(c.getSigAlgName()));
                out.append(",\"key_algorithm\":").append(q(c.getPublicKey().getAlgorithm()));
                out.append(",\"key_bits\":").append(keyBits(c));
                out.append(",\"not_before\":").append(q(c.getNotBefore().toInstant().toString()));
                out.append(",\"not_after\":").append(q(c.getNotAfter().toInstant().toString()));
                out.append(",\"sha256\":").append(q(hex(MessageDigest.getInstance("SHA-256").digest(c.getEncoded()))));
                out.append("}");
                sep = ",";
            }
            out.append("]");
        } catch (Exception e) {
            out.append("\"verified\":false,\"errors\":[").append(q(e.getClass().getSimpleName() + ": " + e.getMessage()))
               .append("],\"signers\":[]");
        }
        System.out.println(out.append("}"));
    }

    static int keyBits(X509Certificate c) {
        Object k = c.getPublicKey();
        if (k instanceof RSAPublicKey) return ((RSAPublicKey) k).getModulus().bitLength();
        if (k instanceof DSAPublicKey) return ((DSAPublicKey) k).getParams().getP().bitLength();
        if (k instanceof ECPublicKey) return ((ECPublicKey) k).getParams().getOrder().bitLength();
        return 0;
    }

    static String strings(List<?> items) {
        List<String> parts = new ArrayList<>();
        for (Object o : items) parts.add(q(String.valueOf(o)));
        return "[" + String.join(",", parts) + "]";
    }

    static String hex(byte[] b) {
        StringBuilder s = new StringBuilder();
        for (byte x : b) s.append(String.format("%02x", x));
        return s.toString();
    }

    static String q(String s) {
        StringBuilder o = new StringBuilder("\"");
        for (char ch : s.toCharArray()) {
            if (ch == '"' || ch == '\\') o.append('\\').append(ch);
            else if (ch < 0x20) o.append(String.format("\\u%04x", (int) ch));
            else o.append(ch);
        }
        return o.append('"').toString();
    }
}
