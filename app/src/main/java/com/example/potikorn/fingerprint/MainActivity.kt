package com.example.potikorn.fingerprint

import android.app.KeyguardManager
import android.content.Context
import android.content.pm.PackageManager
import android.hardware.fingerprint.FingerprintManager
import android.os.Build
import android.support.v7.app.AppCompatActivity
import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.support.annotation.RequiresApi
import android.support.v4.app.ActivityCompat
import android.widget.Toast
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.NoSuchProviderException
import java.util.jar.Manifest
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

class MainActivity : AppCompatActivity(), FingerprintAuthenticatorCallback {

    private lateinit var mFingerprintManager: FingerprintManager
    private lateinit var mKeyguardManager: KeyguardManager

    private val KEY_NAME = "key_name"

    private lateinit var mKeyStore: KeyStore
    private lateinit var mKeyGenerator: KeyGenerator
    private lateinit var cipher: Cipher
    private lateinit var mCryptoObject: FingerprintManager.CryptoObject
    private var mFingerprintHelper: FingerPrintHelper? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        mKeyguardManager = getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        mFingerprintManager = getSystemService(Context.FINGERPRINT_SERVICE) as FingerprintManager

        if (ActivityCompat.checkSelfPermission(this, android.Manifest.permission.USE_FINGERPRINT) != PackageManager.PERMISSION_GRANTED) {
            Toast.makeText(this, "Fingerprint authentication permission not enabled", Toast.LENGTH_LONG).show()
            return
        }

        if (mFingerprintManager.isHardwareDetected) {
            if (!mKeyguardManager.isKeyguardSecure) {
                Toast.makeText(this, "Lock screen security not enabled in Settings", Toast.LENGTH_SHORT).show()
                return
            }
            if (!mFingerprintManager.hasEnrolledFingerprints()) {
                Toast.makeText(this, "Register at least one fingerprint in Settings", Toast.LENGTH_LONG).show()
                return
            }

        }

        generateKey()
        if (initCipher()) {
            mCryptoObject = FingerprintManager.CryptoObject(cipher)
            mFingerprintHelper = FingerPrintHelper(this)
        }
    }

    override fun onResume() {
        super.onResume()
        if (mFingerprintHelper != null) {
            mFingerprintHelper!!.startAuth(mFingerprintManager, mCryptoObject)
            mFingerprintHelper!!.setFingerprintCallback(this)
        }
    }

    override fun onPause() {
        super.onPause()
        if (mFingerprintHelper != null)
            mFingerprintHelper!!.stopListening()
    }

    private fun generateKey() {
        try {
            mKeyStore = KeyStore.getInstance("AndroidKeyStore")
        } catch (e: Exception) {
            e.printStackTrace()
        }

        try {
            mKeyGenerator = KeyGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES,
                    "AndroidKeyStore")
        } catch (e: NoSuchProviderException) {
            throw RuntimeException("Failed to get KeyGenerator instance", e)
        }

        try {
            mKeyStore.load(null)
            mKeyGenerator.init(KeyGenParameterSpec.Builder(KEY_NAME,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setUserAuthenticationRequired(true)
                    .setEncryptionPaddings(
                            KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .build())
            mKeyGenerator.generateKey()
        } catch (e: NoSuchAlgorithmException) {
            throw RuntimeException(e)
        }
    }

    private fun initCipher(): Boolean {
        try {
            cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/"
                    + KeyProperties.BLOCK_MODE_CBC + "/"
                    + KeyProperties.ENCRYPTION_PADDING_PKCS7)
        } catch (e: NoSuchAlgorithmException) {
            throw RuntimeException("Failed to get Cipher", e)
        }

        try {
            mKeyStore.load(null)
            val key: SecretKey = mKeyStore.getKey(KEY_NAME, null) as SecretKey
            cipher.init(Cipher.ENCRYPT_MODE, key)
            return true
        } catch (e: KeyPermanentlyInvalidatedException) {
            return false
        } catch (e: KeyStoreException) {
            throw RuntimeException("Failed to init Cipher", e)
        }
    }

    override fun onFingerprintAuthenticationSuccess() {
        Toast.makeText(this, "Authentication succeeded.", Toast.LENGTH_LONG).show()
    }

    override fun onFingerprintAuthenticationFailed() {
        Toast.makeText(this, "Authentication failed.", Toast.LENGTH_LONG).show()
    }
}
