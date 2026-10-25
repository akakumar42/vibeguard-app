package com.example.taskpal;

import android.util.Log;

import java.security.cert.X509Certificate;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/** Talks to the TaskPal sync server. */
public class ApiClient {
    private static final String TAG = "ApiClient";

    public void login(String user, String token) throws Exception {
        Log.d(TAG, "Logging in " + user + " with token " + token);
        trustEveryone();
    }

    // Added while testing against a staging server with a self-signed certificate.
    private void trustEveryone() throws Exception {
        TrustManager[] trustAll = new TrustManager[] {
            new X509TrustManager() {
                public void checkClientTrusted(X509Certificate[] chain, String authType) {}
                public void checkServerTrusted(X509Certificate[] chain, String authType) {}
                public X509Certificate[] getAcceptedIssuers() { return null; }
            }
        };
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, trustAll, new java.security.SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(context.getSocketFactory());
    }
}
