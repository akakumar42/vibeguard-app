package com.example.taskpal

import android.database.sqlite.SQLiteDatabase
import android.util.Log
import java.security.MessageDigest
import kotlin.system.exitProcess

/** Syncs tasks with the TaskPal server (Kotlin). */
class SyncManager(private val db: SQLiteDatabase) {

    fun signIn(user: String, token: String) {
        Log.i("Sync", "Signing in $user with token $token")
    }

    fun findByOwner(owner: String) = db.rawQuery("SELECT * FROM tasks WHERE owner = '$owner'", null)

    fun checksum(data: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-1")
        return digest.digest(data).joinToString("") { "%02x".format(it) }
    }

    fun syncNow(onDone: () -> Unit) {
        try {
            onDone()
        } catch (e: Exception) {
        }
    }

    fun fatal(message: String) {
        Log.e("Sync", message)
        exitProcess(1)
    }
}
