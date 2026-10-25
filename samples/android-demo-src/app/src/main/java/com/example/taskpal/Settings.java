package com.example.taskpal;

import android.content.Context;
import android.content.SharedPreferences;

/** User settings. */
public class Settings {
    private final SharedPreferences prefs;

    public Settings(Context context) {
        prefs = context.getSharedPreferences("settings", Context.MODE_WORLD_READABLE);
    }

    public boolean isDarkTheme() {
        String theme = prefs.getString("theme", "light");
        return theme == "dark";
    }

    public void saveTheme(String theme) {
        try {
            prefs.edit().putString("theme", theme).apply();
        } catch (Exception e) {
        }
    }
}
