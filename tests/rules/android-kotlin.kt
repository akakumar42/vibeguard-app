// Semgrep rule tests for rules/android-kotlin.yml:  semgrep --test --config rules/android-kotlin.yml tests/rules/
// "ruleid: X" means the next line must be flagged by X; "ok: X" means it must not be.
package test

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.os.Environment
import android.os.Handler
import android.util.Log
import android.webkit.WebView
import java.io.File
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.util.zip.ZipInputStream
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.X509TrustManager
import kotlin.system.exitProcess

class TrustAll : X509TrustManager {
    override fun checkClientTrusted(chain: Array<X509Certificate>?, authType: String?) {}
    // ruleid: trust-all-certificates
    override fun checkServerTrusted(chain: Array<X509Certificate>?, authType: String?) {}
    // ruleid: trust-all-certificates
    override fun getAcceptedIssuers(): Array<X509Certificate>? = null
}

class Checks(private val context: Context, private val db: SQLiteDatabase, private val web: WebView) {

    fun tls() {
        // ruleid: hostname-verifier-allow-all
        HttpsURLConnection.setDefaultHostnameVerifier(HostnameVerifier { _, _ -> true })
        // ruleid: weak-tls-version
        SSLContext.getInstance("TLSv1")
        // ok: weak-tls-version
        SSLContext.getInstance("TLSv1.3")
    }

    fun webview() {
        // ruleid: webview-javascript-enabled
        web.settings.javaScriptEnabled = true
        // ruleid: webview-javascript-interface
        web.addJavascriptInterface(this, "app")
        // ruleid: webview-file-access
        web.settings.allowUniversalAccessFromFileURLs = true
        // ok: webview-file-access
        web.settings.allowFileAccess = false
    }

    fun crypto(pin: String) {
        // ruleid: weak-hash
        MessageDigest.getInstance("MD5")
        // ok: weak-hash
        MessageDigest.getInstance("SHA-256")
        // ruleid: weak-cipher
        Cipher.getInstance("AES/ECB/PKCS5Padding")
        // ok: weak-cipher
        Cipher.getInstance("AES/GCM/NoPadding")
        // ruleid: hardcoded-crypto-key-or-iv
        SecretKeySpec("0123456789abcdef".toByteArray(), "AES")
        // ruleid: hardcoded-crypto-key-or-iv
        IvParameterSpec(ByteArray(16))
    }

    fun storage() {
        // ruleid: world-readable-file
        context.getSharedPreferences("prefs", Context.MODE_WORLD_READABLE)
        // ok: world-readable-file
        context.getSharedPreferences("prefs", Context.MODE_PRIVATE)
        // ruleid: external-storage
        val dir = Environment.getExternalStorageDirectory()
    }

    fun logging(token: String, user: String) {
        // ruleid: sensitive-data-logged
        Log.d("Auth", "token=$token")
        // ok: sensitive-data-logged
        Log.d("Auth", "signed in $user")
    }

    fun sql(name: String) {
        // ruleid: sql-string-concatenation
        db.rawQuery("SELECT * FROM tasks WHERE title = '$name'", null)
        // ruleid: sql-string-concatenation
        db.execSQL("DELETE FROM tasks WHERE list = '" + name + "'")
        // ok: sql-string-concatenation
        db.rawQuery("SELECT * FROM tasks WHERE title = ?", arrayOf(name))
    }

    fun commands(host: String) {
        // ruleid: runtime-exec
        Runtime.getRuntime().exec("ping -c 1 $host")
    }

    fun handlers() {
        // ruleid: handler-without-looper
        val h = Handler()
    }

    fun errors(value: String?) {
        // ruleid: catch-null-pointer
        try {
            value!!.length
        } catch (e: NullPointerException) {
            Log.w("x", "missing")
        }
        // ruleid: empty-catch-block
        try {
            value!!.length
        } catch (e: IllegalStateException) {
        }
        try {
            value!!.length
        } catch (e: Exception) {
            // ruleid: print-stack-trace
            e.printStackTrace()
        }
    }

    fun quit() {
        // ruleid: system-exit
        exitProcess(0)
    }
}

class Unzip {
    fun unsafe(input: ZipInputStream, target: File) {
        var entry = input.nextEntry
        while (entry != null) {
            // ruleid: zip-path-traversal
            val out = File(target, entry.name)
            out.writeBytes(input.readBytes())
            entry = input.nextEntry
        }
    }

    fun safe(input: ZipInputStream, target: File) {
        var entry = input.nextEntry
        while (entry != null) {
            // ok: zip-path-traversal
            val out = File(target, entry.name)
            if (!out.canonicalPath.startsWith(target.canonicalPath + File.separator)) {
                throw SecurityException("Bad zip entry: ${entry.name}")
            }
            out.writeBytes(input.readBytes())
            entry = input.nextEntry
        }
    }

    fun safeWithRequire(input: ZipInputStream, target: File) {
        var entry = input.nextEntry
        while (entry != null) {
            // ok: zip-path-traversal
            val out = File(target, entry.name)
            require(out.canonicalPath.startsWith(target.canonicalPath + File.separator)) { "Bad zip entry" }
            out.writeBytes(input.readBytes())
            entry = input.nextEntry
        }
    }

    fun notAZip(dir: File, item: File) {
        // ok: zip-path-traversal
        val out = File(dir, item.name)
    }
}
