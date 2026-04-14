package design.codeux.biometric_storage

import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import io.github.oshai.kotlinlogging.KotlinLogging
import java.io.File
import android.security.keystore.UserNotAuthenticatedException
import io.github.oshai.kotlinlogging.Level
import javax.crypto.IllegalBlockSizeException
import java.security.KeyStoreException
import java.io.IOException
import java.security.KeyStore
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec

private val logger = KotlinLogging.logger {}

data class InitOptions(
    val authenticationValidityDurationSeconds: Int = -1,
    val authenticationRequired: Boolean = true,
    val androidBiometricOnly: Boolean = true
)

class MigrationRequiredException(cause: Throwable? = null) :
    RuntimeException("MigrationRequired", cause)

class BiometricStorageFile(
    val context: Context,
    baseName: String,
    val options: InitOptions
) {

    companion object {
        /**
         * Name of directory inside private storage where all encrypted files are stored.
         */
        private const val DIRECTORY_NAME = "biometric_storage"
        private const val FILE_SUFFIX_V2 = ".v2.txt"
        private const val SANDBOX_FLAG_ALIAS = "_CM_is_sandbox_work"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    }

    private val masterKeyName = "${baseName}_master_key"
    private val fileNameV2 = "$baseName$FILE_SUFFIX_V2"
    private val fileV2: File

    private val canUseStrongBox: Boolean by lazy {
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
                context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE) &&
                testStrongBoxSupport(context)
    }

    private val forceDisableStrongBox: Boolean by lazy {
        hasSandboxFlag()
    }

    private var cryptographyManager = CryptographyManager {
        logToAndroid(Level.DEBUG, "🧩 init cryptographyManager")
        setUserAuthenticationRequired(options.authenticationRequired)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            if (forceDisableStrongBox) {
                logToAndroid(Level.DEBUG, "🧩 StrongBox DISABLED by migration flag for $masterKeyName")
                logger.debug { "StrongBox DISABLED by migration flag for $masterKeyName" }
                setIsStrongBoxBacked(false)
            } else if (canUseStrongBox) {
                logToAndroid(Level.DEBUG, "🧩 Using StrongBox-backed key for $masterKeyName")
                logger.debug { "Using StrongBox-backed key for $masterKeyName" }
                setIsStrongBoxBacked(true)
            } else {
                logToAndroid(Level.DEBUG, "🧩 StrongBox not available, using TEE for $masterKeyName")
                logger.debug { "StrongBox not available, using TEE for $masterKeyName" }
                setIsStrongBoxBacked(false)
            }
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            if (options.authenticationValidityDurationSeconds == -1) {
                setUserAuthenticationParameters(
                    0,
                    KeyProperties.AUTH_BIOMETRIC_STRONG
                )
            } else {
                setUserAuthenticationParameters(
                    options.authenticationValidityDurationSeconds,
                    KeyProperties.AUTH_DEVICE_CREDENTIAL or KeyProperties.AUTH_BIOMETRIC_STRONG
                )
            }
        } else {
            @Suppress("DEPRECATION")
            setUserAuthenticationValidityDurationSeconds(options.authenticationValidityDurationSeconds)
        }
    }

    init {
        val baseDir = File(context.filesDir, DIRECTORY_NAME)
        if (!baseDir.exists()) {
            baseDir.mkdirs()
        }
        fileV2 = File(baseDir, fileNameV2)

        logger.trace { "Initialized $this with $options" }

        validateOptions()
    }

    private fun validateOptions() {
        if (options.authenticationValidityDurationSeconds == -1 && !options.androidBiometricOnly) {
            throw IllegalArgumentException("when authenticationValidityDurationSeconds is -1, androidBiometricOnly must be true")
        }
    }

    fun cipherForEncrypt() = cryptographyManager.getInitializedCipherForEncryption(masterKeyName)
    fun cipherForDecrypt(): Cipher? {
        if (fileV2.exists()) {
            return cryptographyManager.getInitializedCipherForDecryption(masterKeyName, fileV2)
        }
        logger.debug { "No file exists, no IV found. null cipher." }
        return null
    }

    fun exists() = fileV2.exists()

    @Synchronized
    fun writeFile(cipher: Cipher?, content: String) {
        logToAndroid(Level.DEBUG, "🧩writeFile")
        try {
            val useCipher = cipher ?: cipherForEncrypt()
            val encrypted = cryptographyManager.encryptData(content, useCipher)
            fileV2.writeBytes(encrypted.encryptedPayload)
            logger.debug { "Successfully written ${encrypted.encryptedPayload.size} bytes." }

            return
        } catch (ex: IOException) {
            // Error occurred opening file for writing.
            logger.error(ex) { "Error while writing encrypted file $fileV2" }
            throw ex
        } catch (ex: KeyPermanentlyInvalidatedException) {
            logger.error(ex) {
                "KeyPermanentlyInvalidatedException while encrypting $fileV2 — triggering migration"
            }
            logToAndroid(
                Level.DEBUG,
                "🧩KeyPermanentlyInvalidatedException while encrypting $fileV2 — triggering migration"
            )
            safeDeleteKeyAndFile()
            throw MigrationRequiredException(ex)
        }
    }


    @Synchronized
    fun readFile(cipher: Cipher?): String? {
        if (!fileV2.exists()) {
            logger.debug { "File $fileV2 does not exist. returning null." }
            return null
        }

        val useCipher = try {
            cipher ?: cipherForDecrypt()
        } catch (ex: KeyPermanentlyInvalidatedException) {
            logger.error(ex) {
                "KeyPermanentlyInvalidatedException while opening cipher for $fileV2 — biometric enrollment changed, triggering migration"
            }
            logToAndroid(
                Level.DEBUG,
                "🧩KeyPermanentlyInvalidatedException while opening cipher for $fileV2 — triggering migration"
            )
            safeDeleteKeyAndFile()
            throw MigrationRequiredException(ex)
        }

        if (useCipher == null) {
            return null
        }

        return try {
            val bytes = fileV2.readBytes()
            logger.debug { "read ${bytes.size} bytes from $fileV2" }
            cryptographyManager.decryptData(bytes, useCipher)
        } catch (ex: IOException) {
            logger.error(ex) { "IO error while reading encrypted file $fileV2" }
            null
        } catch (@SuppressLint("NewApi") ex: AEADBadTagException) {
            logger.error(ex) {
                "AEADBadTagException while decrypting $fileV2 — deleting key+file and triggering migration"
            }
            logToAndroid(
                Level.DEBUG,
                "🧩AEADBadTagException while decrypting $fileV2 — deleting key+file and triggering migration"
            )
            safeDeleteKeyAndFile()
            setSandboxFlag()
            throw MigrationRequiredException()
        } catch (ex: IllegalBlockSizeException) {
            logger.error(ex) {
                "IllegalBlockSizeException while decrypting $fileV2 — deleting key+file and triggering migration"
            }
            logToAndroid(
                Level.DEBUG,
                "🧩IllegalBlockSizeException while decrypting $fileV2 — deleting key+file and triggering migration"
            )
            safeDeleteKeyAndFile()
            setSandboxFlag()
            throw MigrationRequiredException(ex)
        } catch (ex: KeyPermanentlyInvalidatedException) {
            logger.error(ex) {
                "KeyPermanentlyInvalidatedException while decrypting $fileV2 — biometric enrollment changed, triggering migration"
            }
            logToAndroid(
                Level.DEBUG,
                "🧩KeyPermanentlyInvalidatedException while decrypting $fileV2 — triggering migration"
            )
            safeDeleteKeyAndFile()
            throw MigrationRequiredException(ex)
        } catch (ex: Exception) {
            //TODO what about wrong finger or face
            logger.error(ex) {
                "Unexpected crypto error while decrypting $fileV2 — deleting key+file and triggering migration"
            }
            logToAndroid(
                Level.DEBUG,
                "Unexpected crypto error while decrypting $fileV2 — deleting key+file and triggering migration"
            )
            safeDeleteKeyAndFile()
            setSandboxFlag()
            throw MigrationRequiredException(ex)
        }

    }

    @Synchronized
    fun deleteFile(): Boolean {
        cryptographyManager.deleteKey(masterKeyName)
        return fileV2.delete()
    }

    override fun toString(): String {
        return "BiometricStorageFile(masterKeyName='$masterKeyName', fileName='$fileNameV2', file=$fileV2)"
    }

    fun dispose() {
        logger.trace { "dispose" }
    }

    private fun testStrongBoxSupport(context: Context): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) return false

        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val testKeyName = "STRONGBOX_TEST_KEY"

        return try {
            val builder = KeyGenParameterSpec.Builder(
                testKeyName,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUserAuthenticationRequired(true)
                .setIsStrongBoxBacked(true)

            val keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES,
                "AndroidKeyStore"
            )
            keyGenerator.init(builder.build())
            val key = keyGenerator.generateKey()

            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key)
            val iv = cipher.iv
            val encrypted = cipher.doFinal("test".toByteArray())

            val decCipher = Cipher.getInstance("AES/GCM/NoPadding")
            decCipher.init(
                Cipher.DECRYPT_MODE,
                key,
                GCMParameterSpec(128, iv)
            )
            val decrypted = String(decCipher.doFinal(encrypted))

            decrypted == "test"
        } catch (e: Exception) {
            false
        } finally {
            try {
                ks.deleteEntry(testKeyName)
            } catch (_: Exception) {
            }
        }
    }

    private fun hasSandboxFlag(): Boolean {
        return try {
            val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            ks.containsAlias(SANDBOX_FLAG_ALIAS)
        } catch (e: Exception) {
            logger.error(e) { "Error checking sandbox flag" }
            false
        }
    }

    private fun setSandboxFlag() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            logger.warn { "Sandbox flag not supported on API < 23" }
            return
        }

        try {
            val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            if (ks.containsAlias(SANDBOX_FLAG_ALIAS)) return

            val generator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES,
                ANDROID_KEYSTORE
            )

            val spec = KeyGenParameterSpec.Builder(
                SANDBOX_FLAG_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setKeySize(128)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setUserAuthenticationRequired(false)
                .build()

            generator.init(spec)
            generator.generateKey()

            logger.warn { "Sandbox flag created — StrongBox disabled for future keys" }

        } catch (e: Exception) {
            logger.error(e) { "Failed to create sandbox flag" }
        }
    }

    private fun safeDeleteKeyAndFile() {
        try {
            cryptographyManager.deleteKey(masterKeyName)
        } catch (e: Exception) {
            logger.warn(e) { "Failed to delete master key $masterKeyName during migration" }
        }

        try {
            if (fileV2.exists()) {
                fileV2.delete()
            }
        } catch (e: Exception) {
            logger.warn(e) { "Failed to delete file $fileV2 during migration" }
        }
    }
}
