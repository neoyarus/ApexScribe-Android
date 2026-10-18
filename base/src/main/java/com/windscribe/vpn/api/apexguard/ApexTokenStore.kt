package com.windscribe.vpn.api.apexguard

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import com.google.gson.JsonParser
import dagger.hilt.android.qualifiers.ApplicationContext
import java.security.KeyStore
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class ApexTokenStore
    @Inject
    constructor(
        @ApplicationContext context: Context,
    ) {
        private val preferences = context.getSharedPreferences("apexguard_secure", Context.MODE_PRIVATE)
        private val alias = "apexguard.session.v1"

        private fun key(): SecretKey {
            val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            (store.getKey(alias, null) as? SecretKey)?.let { return it }
            return KeyGenerator
                .getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
                .apply {
                    init(
                        KeyGenParameterSpec
                            .Builder(
                                alias,
                                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
                            ).setBlockModes(
                                KeyProperties.BLOCK_MODE_GCM,
                            ).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                            .setRandomizedEncryptionRequired(true)
                            .build(),
                    )
                }.generateKey()
        }

        @Synchronized fun load(): ApexTokens? {
            if (preferences.getBoolean("signed_out", false)) return null
            val stored = preferences.getString("session", null) ?: return null
            return try {
                val bytes = Base64.decode(stored, Base64.NO_WRAP)
                require(bytes.size > 28)
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, bytes.copyOfRange(0, 12)))
                cipher.updateAAD(alias.toByteArray(Charsets.UTF_8))
                ApexContracts.tokens(
                    JsonParser.parseString(String(cipher.doFinal(bytes.copyOfRange(12, bytes.size)), Charsets.UTF_8)).asJsonObject,
                )
            } catch (_: Exception) {
                // A restored backup or invalidated keystore key must never restore a session.
                clear()
                null
            }
        }

        @Synchronized fun save(tokens: ApexTokens) {
            val plain =
                com.google.gson
                    .JsonObject()
                    .apply {
                        addProperty("access_token", tokens.access)
                        addProperty("refresh_token", tokens.refresh)
                    }.toString()
                    .toByteArray(Charsets.UTF_8)
            try {
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.ENCRYPT_MODE, key())
                cipher.updateAAD(alias.toByteArray(Charsets.UTF_8))
                val encoded = Base64.encodeToString(cipher.iv + cipher.doFinal(plain), Base64.NO_WRAP)
                if (!preferences
                        .edit()
                        .putString(
                            "session",
                            encoded,
                        ).putBoolean("signed_out", false)
                        .commit()
                ) {
                    throw ApexApiException("storage_failed")
                }
            } finally {
                plain.fill(0)
            }
        }

        @Synchronized fun clear() {
            // Commit the tombstone first so a failed deletion cannot resurrect a signed-out session.
            if (!preferences.edit().putBoolean("signed_out", true).commit()) throw ApexApiException("storage_failed")
            if (!preferences.edit().remove("session").commit()) throw ApexApiException("storage_failed")
        }

        @Synchronized fun deviceId(): String {
            preferences.getString("device_id", null)?.let { value ->
                if (runCatching { UUID.fromString(value).version() == 4 }.getOrDefault(false)) return value
            }
            val id = UUID.randomUUID().toString()
            if (!preferences.edit().putString("device_id", id).commit()) throw ApexApiException("storage_failed")
            return id
        }

        var gateway: String?
            get() = preferences.getString("gateway", null)?.takeIf(ApexContracts::gateway)
            set(value) {
                if (value != null && ApexContracts.gateway(value)) preferences.edit().putString("gateway", value).apply()
            }
    }
