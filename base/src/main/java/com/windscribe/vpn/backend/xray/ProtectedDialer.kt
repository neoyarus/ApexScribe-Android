package com.windscribe.vpn.backend.xray

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import java.io.Closeable
import java.io.DataInputStream
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
                launch { forward(client) }
            }
        }

    private suspend fun forward(client: Socket) {
        var upstream: Socket? = null
        try {
            client.soTimeout = 10_000
            val input = DataInputStream(client.getInputStream())
            val output = client.getOutputStream()
            require(input.readUnsignedByte() == 5)
            val methods = ByteArray(input.readUnsignedByte()).also(input::readFully)
            require(methods.contains(2.toByte()))
            output.write(byteArrayOf(5, 2))
            output.flush()
            require(input.readUnsignedByte() == 1)
            val user = ByteArray(input.readUnsignedByte()).also(input::readFully)
            val pass = ByteArray(input.readUnsignedByte()).also(input::readFully)
            require(MessageDigest.isEqual(user, username.toByteArray()) && MessageDigest.isEqual(pass, password.toByteArray()))
            output.write(byteArrayOf(1, 0))
            output.flush()
            require(input.readUnsignedByte() == 5 && input.readUnsignedByte() == 1 && input.readUnsignedByte() == 0)
            val address =
                when (input.readUnsignedByte()) {
                    1 -> InetAddress.getByAddress(ByteArray(4).also(input::readFully))
                    4 -> InetAddress.getByAddress(ByteArray(16).also(input::readFully))
                    // Hostnames are deliberately rejected: DNS was resolved before establishing TUN.
                    else -> error("Unsupported dialer destination")
                }
            require(address == endpoint && input.readUnsignedShort() == endpointPort)
            upstream = Socket()
            sockets.add(upstream)
            check(protectSocket(upstream)) { "VPN socket protection failed" }
            upstream.connect(InetSocketAddress(endpoint, endpointPort), 15_000)
            upstream.tcpNoDelay = true
            client.tcpNoDelay = true
            client.soTimeout = 0
            output.write(byteArrayOf(5, 0, 0, 1, 0, 0, 0, 0, 0, 0))
            output.flush()
            val remote = upstream
            val send =
                scope.launch(Dispatchers.IO) {
                    try {
                        input.copyTo(remote.getOutputStream())
                    } finally {
                        runCatching { remote.shutdownOutput() }
                    }
                }
            try {
                remote.getInputStream().copyTo(output)
            } finally {
                runCatching { client.shutdownOutput() }
                remote.close()
                client.close()
                send.cancelAndJoin()
            }
        } catch (_: Exception) {
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

    override fun close() {
        listener.close()
        acceptJob.cancel()
        sockets.forEach { runCatching { it.close() } }
        sockets.clear()
    }
}
