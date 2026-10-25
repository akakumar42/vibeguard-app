package com.example.taskpal;

/** Build-time configuration. */
public final class Config {
    public static final String SYNC_URL = "https://sync.taskpal.example/api";
    // Fake demo key: planted on purpose so the scan can show a leaked secret.
    public static final String STRIPE_SECRET_KEY = "sk_live_51NfakeDemoKeyOnly4TaskPalXyZ0123456789abcd";

    private Config() {}
}
