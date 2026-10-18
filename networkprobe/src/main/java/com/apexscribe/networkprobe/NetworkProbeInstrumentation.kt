package com.apexscribe.networkprobe

import android.app.Activity
import android.app.Instrumentation
import android.os.Bundle
import android.os.Process
import java.net.URL
import java.util.UUID
import javax.net.ssl.HttpsURLConnection

/** A fresh, ordinary HTTPS socket from an independent app UID, with no VPN binding. */
class NetworkProbeInstrumentation : Instrumentation() {
    private var probeId = ""

    override fun onCreate(arguments: Bundle?) {
        super.onCreate(arguments)
        probeId = arguments?.getString("probe_id").orEmpty()
        start()
    }

    override fun onStart() {
        val results = Bundle()
        results.putString("probe_id", probeId)
        results.putInt("probe_uid", Process.myUid())
        try {
            require(probeId.length <= 64 && probeId.all { it.isLetterOrDigit() || it == '-' })
            val connection = URL("https://api.ipify.org/?probe=${UUID.randomUUID()}").openConnection() as HttpsURLConnection
            try {
                connection.connectTimeout = 12_000
                connection.readTimeout = 12_000
                connection.useCaches = false
                connection.instanceFollowRedirects = false
                connection.setRequestProperty("Connection", "close")
                check(connection.responseCode == HttpsURLConnection.HTTP_OK)
                val value =
                    connection.inputStream.use { input ->
                        val bytes = ByteArray(128)
                        var size = 0
                        while (size < bytes.size) {
                            val read = input.read(bytes, size, bytes.size - size)
                            if (read < 0) break
                            size += read
                        }
                        String(bytes, 0, size, Charsets.US_ASCII).trim()
                    }
                require(isIpv4(value))
                results.putString("exit_ip", value)
                finish(Activity.RESULT_OK, results)
            } finally {
                connection.disconnect()
            }
        } catch (failure: Exception) {
            results.putString("probe_error", failure.javaClass.simpleName)
            finish(Activity.RESULT_CANCELED, results)
        }
    }

    private fun isIpv4(value: String): Boolean {
        val octets = value.split('.')
        return octets.size == 4 && octets.all { it.isNotEmpty() && it.length <= 3 && it.all(Char::isDigit) && it.toInt() in 0..255 }
    }
}
