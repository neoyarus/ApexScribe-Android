package com.windscribe.mobile

import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.windscribe.vpn.api.apexguard.ApexVless
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.lang.reflect.Proxy
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.SecureRandom
import java.util.Base64

/** Exercises shipped Android native libraries, without an account or remote connection. */
@RunWith(AndroidJUnit4::class)
class XrayNativeSmokeTest {
    @Test fun generatedRawAndGrpcConfigsStartAndStopBundledCore() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        // Reflection keeps the production config generator internal to base. These
        // classes are packaged by base's private AAR dependencies.
        Class.forName("go.Seq").getMethod("setContext", Context::class.java).invoke(null, context)
        val library = Class.forName("libv2ray.Libv2ray")
        val callbackType = Class.forName("libv2ray.CoreCallbackHandler")
        val callback =
            Proxy.newProxyInstance(callbackType.classLoader, arrayOf(callbackType)) { proxy, method, args ->
                when (method.name) {
                    "hashCode" -> System.identityHashCode(proxy)
                    "equals" -> proxy === args?.firstOrNull()
                    "toString" -> "NativeSmokeCallback"
                    else -> 0L
                }
            }
        val key = ByteArray(32).also { SecureRandom().nextBytes(it) }
        library.getMethod("initCoreEnv", String::class.java, String::class.java).invoke(
            null,
            context.filesDir.absolutePath,
            Base64.getUrlEncoder().withoutPadding().encodeToString(key),
        )
        val generator = Class.forName("com.windscribe.vpn.backend.xray.XrayConfig")
        val create =
            generator.getMethod(
                "create",
                ApexVless::class.java,
                String::class.java,
                Int::class.javaPrimitiveType,
                String::class.java,
                String::class.java,
                Int::class.javaPrimitiveType,
                String::class.java,
                String::class.java,
                Int::class.javaObjectType,
            )
        val instance = generator.getField("INSTANCE").get(null)
        val core = library.getMethod("newCoreController", callbackType).invoke(null, callback)
        val start = core.javaClass.getMethod("startLoop", String::class.java, Int::class.javaPrimitiveType)
        val stop = core.javaClass.getMethod("stopLoop")
        val running = core.javaClass.getMethod("getIsRunning")
        for (transport in listOf("raw", "grpc")) {
            val port = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1")).use { it.localPort }
            val grant =
                ApexVless(
                    "de04add9-5c68-4bab-950c-08cd5320df18",
                    "vpn.example.com",
                    443,
                    transport,
                    "example.com",
                    "w6Qe7jmsr3ODd08qpfBC_0hVOmCkhpEFuqNTBFQFwQo",
                    "aabb",
                    "chrome",
                    "/",
                    if (transport == "raw") "xtls-rprx-vision" else "",
                    "example-service",
                    false,
                )
            val json =
                create.invoke(
                    instance,
                    grant,
                    "203.0.113.9",
                    port,
                    "test-user",
                    "test-password",
                    9,
                    "dialer-user",
                    "dialer-password",
                    null,
                ) as String
            try {
                start.invoke(core, json, 0)
                assertTrue("Bundled core did not start for $transport", running.invoke(core) as Boolean)
                Socket("127.0.0.1", port).use { socket ->
                    socket.soTimeout = 3_000
                    // Prove the generated inbound is served by this native core and
                    // actually requires password authentication. No CONNECT is sent.
                    socket.getOutputStream().write(byteArrayOf(5, 1, 2))
                    assertEquals(5, socket.getInputStream().read())
                    assertEquals(2, socket.getInputStream().read())
                }
            } finally {
                stop.invoke(core)
            }
            assertFalse("Bundled core stayed running after stop", running.invoke(core) as Boolean)
        }
        val hev = Class.forName("hev.htproxy.TProxyService")
        assertFalse("TUN worker unexpectedly running", hev.getMethod("TProxyIsRunning").invoke(null) as Boolean)
        assertTrue(hev.getMethod("TProxyStopService").invoke(null) as Boolean)
    }
}
