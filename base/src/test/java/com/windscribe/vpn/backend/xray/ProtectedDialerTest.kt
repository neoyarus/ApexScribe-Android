package com.windscribe.vpn.backend.xray

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.DataInputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.atomic.AtomicInteger

class ProtectedDialerTest {
    private val loopback = InetAddress.getByName("127.0.0.1")

    private fun authenticate(
        socket: Socket,
        dialer: ProtectedDialer,
    ) {
        socket.soTimeout = 3_000
        val output = socket.getOutputStream()
        val input = DataInputStream(socket.getInputStream())
        output.write(byteArrayOf(5, 1, 2))
        assertEquals(5, input.readUnsignedByte())
        assertEquals(2, input.readUnsignedByte())
        val user = dialer.username.toByteArray()
        val password = dialer.password.toByteArray()
        output.write(byteArrayOf(1, user.size.toByte()) + user + byteArrayOf(password.size.toByte()) + password)
        assertEquals(1, input.readUnsignedByte())
        assertEquals(0, input.readUnsignedByte())
    }

    private fun request(
        socket: Socket,
        port: Int,
    ) {
        socket.getOutputStream().write(byteArrayOf(5, 1, 0, 1, 127, 0, 0, 1, (port shr 8).toByte(), port.toByte()))
    }

    @Test fun upstreamIsProtectedBeforeConnectAndBytesRoundTrip() =
        runBlocking {
            val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
            val calls = AtomicInteger()
            ServerSocket(0, 1, loopback).use { upstream ->
                ProtectedDialer(scope, loopback, upstream.localPort) { socket ->
                    assertFalse(socket.isConnected)
                    calls.incrementAndGet()
                    true
                }.use { dialer ->
                    val echo =
                        scope.launch {
                            upstream.accept().use { socket -> socket.getOutputStream().write(socket.getInputStream().read()) }
                        }
                    Socket(loopback, dialer.port).use { client ->
                        authenticate(client, dialer)
                        request(client, upstream.localPort)
                        val input = DataInputStream(client.getInputStream())
                        val reply = ByteArray(10).also(input::readFully)
                        assertEquals(0, reply[1].toInt())
                        client.getOutputStream().write(42)
                        assertEquals(42, input.readUnsignedByte())
                    }
                    echo.join()
                    assertEquals(1, calls.get())
                }
            }
            scope.cancel()
        }

    @Test fun failedSocketProtectionPreventsAnyUpstreamConnect() {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        val calls = AtomicInteger()
        ServerSocket(0, 1, loopback).use { upstream ->
            upstream.soTimeout = 300
            ProtectedDialer(scope, loopback, upstream.localPort) {
                calls.incrementAndGet()
                false
            }.use { dialer ->
                Socket(loopback, dialer.port).use { client ->
                    authenticate(client, dialer)
                    request(client, upstream.localPort)
                    assertEquals(-1, client.getInputStream().read())
                }
                assertEquals(1, calls.get())
                assertTrue(runCatching { upstream.accept() }.isFailure)
            }
        }
        scope.cancel()
    }

    @Test fun otherDestinationIsRejectedBeforeOpeningProtectedSocket() {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        val calls = AtomicInteger()
        ProtectedDialer(scope, loopback, 443) {
            calls.incrementAndGet()
            true
        }.use { dialer ->
            Socket(loopback, dialer.port).use { client ->
                authenticate(client, dialer)
                request(client, 444)
                assertEquals(-1, client.getInputStream().read())
            }
            assertEquals(0, calls.get())
        }
        scope.cancel()
    }
}
