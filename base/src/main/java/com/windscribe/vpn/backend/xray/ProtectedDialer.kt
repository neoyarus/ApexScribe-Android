package com.windscribe.vpn.backend.xray

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import java.io.Closeable
import java.io.DataInputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * AndroidLibXrayLite does not expose a socket protection callback. Its dialerProxy
 * sends the outer transport here, where the actual upstream socket is protected
 * before connect. Only the resolved grant endpoint is accepted; there is no
 * general purpose direct outbound available to Xray or another local process.
 */
internal class ProtectedDialer(
    private val scope: CoroutineScope,
    private val endpoint: InetAddress,
    private val endpointPort: Int,
    private val protectSocket: (Socket) -> Boolean,
) : Closeable {
    val username = UUID.randomUUID().toString()
    val password = UUID.randomUUID().toString()
    private val listener = ServerSocket(0, 16, InetAddress.getByName("127.0.0.1"))
    val port: Int get() = listener.localPort
    private val sockets = ConcurrentHashMap.newKeySet<Socket>()
    private val acceptJob: Job =
        scope.launch(Dispatchers.IO) {
            while (!listener.isClosed) {
                val client =
                    try {
                        listener.accept()
                    } catch (_: Exception) {
                        break
                    }
                sockets.add(client)
                XrayDiagnostics.count("accepted")
                launch { forward(client) }
            }
        }

    private suspend fun forward(client: Socket) {
        var upstream: Socket? = null
        var stage = "methods"
        try {
            client.soTimeout = 10_000
            val input = DataInputStream(client.getInputStream())
            val output = client.getOutputStream()
            require(input.readUnsignedByte() == 5)
            val methods = ByteArray(input.readUnsignedByte()).also(input::readFully)
            require(methods.contains(2.toByte()))
            output.write(byteArrayOf(5, 2))
            output.flush()
            stage = "auth"
            require(input.readUnsignedByte() == 1)
            val user = ByteArray(input.readUnsignedByte()).also(input::readFully)
            val pass = ByteArray(input.readUnsignedByte()).also(input::readFully)
            require(MessageDigest.isEqual(user, username.toByteArray()) && MessageDigest.isEqual(pass, password.toByteArray()))
            output.write(byteArrayOf(1, 0))
            output.flush()
            XrayDiagnostics.count("authenticated")
            stage = "command"
            require(input.readUnsignedByte() == 5 && input.readUnsignedByte() == 1 && input.readUnsignedByte() == 0)
            val address =
                when (val type = input.readUnsignedByte().also { XrayDiagnostics.count("atyp_$it") }) {
                    1 -> InetAddress.getByAddress(ByteArray(4).also(input::readFully))
                    4 -> InetAddress.getByAddress(ByteArray(16).also(input::readFully))
                    // Hostnames are deliberately rejected: DNS was resolved before establishing TUN.
                    else -> error("Unsupported dialer destination")
                }
            require(address == endpoint && input.readUnsignedShort() == endpointPort)
            XrayDiagnostics.count("destination_accepted")
            stage = "bind"
            upstream = Socket()
            sockets.add(upstream)
            // Android Socket() creates only its Java implementation. VpnService
            // protect(Socket) reads the descriptor directly without createImpl,
            // so force a real, unconnected FD before asking Android to protect it.
            upstream.bind(InetSocketAddress(0))
            XrayDiagnostics.count("bound")
            stage = "protect"
            check(protectSocket(upstream)) { "VPN socket protection failed" }
            XrayDiagnostics.count("protected")
            stage = "connect"
            upstream.connect(InetSocketAddress(endpoint, endpointPort), 15_000)
            XrayDiagnostics.count("connected")
            upstream.tcpNoDelay = true
            client.tcpNoDelay = true
            client.soTimeout = 0
            output.write(byteArrayOf(5, 0, 0, 1, 0, 0, 0, 0, 0, 0))
            output.flush()
            stage = "relay"
            val remote = upstream
            val send =
                scope.launch(Dispatchers.IO) {
                    try {
                        copyCounted(input, remote.getOutputStream(), "upstream_bytes")
                    } catch (cancelled: CancellationException) {
                        throw cancelled
                    } catch (_: IOException) {
                        // Closing either end during disconnect wakes this blocking
                        // relay with SocketException. A root launch must consume it,
                        // rather than invoking Android's uncaught exception handler.
                        XrayDiagnostics.count("upstream_closed")
                    } finally {
                        runCatching { remote.shutdownOutput() }
                    }
                }
            try {
                copyCounted(remote.getInputStream(), output, "downstream_bytes")
            } finally {
                runCatching { client.shutdownOutput() }
                remote.close()
                client.close()
                send.cancelAndJoin()
            }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            XrayDiagnostics.count("failed_$stage")
            XrayDiagnostics.fail("dialer_$stage")
            // Endpoint and credentials must never appear in logs or UI errors.
        } finally {
            runCatching { client.close() }
            sockets.remove(client)
            upstream?.let {
                runCatching { it.close() }
                sockets.remove(it)
            }
        }
    }

    private fun copyCounted(
        input: InputStream,
        output: OutputStream,
        counter: String,
    ) {
        val buffer = ByteArray(16 * 1024)
        while (true) {
            val count = input.read(buffer)
            if (count < 0) return
            output.write(buffer, 0, count)
            XrayDiagnostics.count(counter, count.toLong())
        }
    }

    override fun close() {
        listener.close()
        acceptJob.cancel()
        sockets.forEach { runCatching { it.close() } }
        sockets.clear()
    }
}
