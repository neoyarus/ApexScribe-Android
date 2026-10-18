package com.apexscribe.networkprobe

import android.app.Activity
import android.app.Instrumentation
import android.os.Bundle
import android.os.Process
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL
import java.util.UUID
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLSocketFactory

/** A fresh, ordinary HTTPS socket from an independent app UID, with no VPN binding. */
class NetworkProbeInstrumentation : Instrumentation() {
    private var probeId = ""
    private var destinationIpv4: String? = null
    private var lanIp: String? = null
    private var lanPort = 0

    override fun onCreate(arguments: Bundle?) {
        super.onCreate(arguments)
        probeId = arguments?.getString("probe_id").orEmpty()
        destinationIpv4 = arguments?.getString("destination_ipv4")
        lanIp = arguments?.getString("lan_ip")
        lanPort = arguments?.getString("lan_port")?.toIntOrNull() ?: 0
        start()
    }

    override fun onStart() {
        val results = Bundle()
        results.putString("probe_id", probeId)
        results.putInt("probe_uid", Process.myUid())
        try {
            require(probeId.length <= 64 && probeId.all { it.isLetterOrDigit() || it == '-' })
            lanIp?.let { address ->
                require(isIpv4(address) && lanPort in 1..65535)
                val reachable =
                    try {
                        val nonce = "apex-lan-${UUID.randomUUID()}"
                        Socket().use { socket ->
                            socket.soTimeout = 4_000
                            socket.connect(InetSocketAddress(address, lanPort), 4_000)
                            socket.getOutputStream().apply {
                                write("$nonce\n".toByteArray(Charsets.US_ASCII))
                                flush()
                            }
                            // A tun proxy may acknowledge SYN locally. Require an application
                            // response from the controlled physical-LAN listener to prove routing.
                            val input = socket.getInputStream()
                            val response = StringBuilder()
                            while (response.length < 256) {
                                val next = input.read()
                                if (next == -1 || next == '\n'.code) break
                                response.append(next.toChar())
                            }
                            response.toString() == nonce
                        }
                    } catch (_: java.io.IOException) {
                        false
                    }
                results.putString("lan_reachable", reachable.toString())
                finish(Activity.RESULT_OK, results)
                return
            }
            val connection = URL("https://api.ipify.org/?probe=${UUID.randomUUID()}").openConnection() as HttpsURLConnection
            try {
                destinationIpv4?.let { address ->
                    require(isIpv4(address))
                    // Keep the URL, SNI, and platform certificate/hostname checks for api.ipify.org.
                    // Only the ordinary, unbound TCP destination changes; no Network.bindSocket.
                    connection.sslSocketFactory = PinnedDestinationFactory(address, connection.sslSocketFactory)
                    results.putString("destination_ipv4", address)
                }
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

    private class PinnedDestinationFactory(
        address: String,
        private val delegate: SSLSocketFactory,
    ) : SSLSocketFactory() {
        private val destination = InetAddress.getByName(address)

        override fun getDefaultCipherSuites(): Array<String> = delegate.defaultCipherSuites

        override fun getSupportedCipherSuites(): Array<String> = delegate.supportedCipherSuites

        // Android HttpsURLConnection connects TCP first, then asks for this layered TLS socket.
        override fun createSocket(
            socket: Socket,
            host: String,
            port: Int,
            autoClose: Boolean,
        ): Socket {
            require(host == "api.ipify.org" && port == 443)
            socket.close()
            val pinned = Socket()
            try {
                pinned.connect(InetSocketAddress(destination, port), 12_000)
                return delegate.createSocket(pinned, host, port, true)
            } catch (failure: Exception) {
                pinned.close()
                throw failure
            }
        }

        override fun createSocket(
            host: String,
            port: Int,
        ): Socket = createSocket(Socket(), host, port, true)

        override fun createSocket(
            host: String,
            port: Int,
            local: InetAddress,
            localPort: Int,
        ): Socket = createSocket(host, port)

        override fun createSocket(
            host: InetAddress,
            port: Int,
        ): Socket = createSocket("api.ipify.org", port)

        override fun createSocket(
            host: InetAddress,
            port: Int,
            local: InetAddress,
            localPort: Int,
        ): Socket = createSocket("api.ipify.org", port)

        // Fail explicitly on an unfamiliar HTTPS stack instead of silently probing an unpinned IP.
        override fun createSocket(): Socket = error("This HTTPS stack must use layered TLS sockets")
    }
}
