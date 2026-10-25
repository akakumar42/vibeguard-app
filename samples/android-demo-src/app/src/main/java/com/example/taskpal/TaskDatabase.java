package com.example.taskpal;

import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;

/** Search over the user's tasks. */
public class TaskDatabase {
    private final SQLiteDatabase db;

    public TaskDatabase(SQLiteDatabase db) {
        this.db = db;
    }

    public Cursor search(String text) {
        return db.rawQuery("SELECT * FROM tasks WHERE title LIKE '%" + text + "%'", null);
    }

    public void deleteList(String listName) {
        db.execSQL("DELETE FROM tasks WHERE list = '" + listName + "'");
    }
}
