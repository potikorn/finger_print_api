package com.example.potikorn.fingerprint

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.hardware.fingerprint.FingerprintManager
import android.os.CancellationSignal
import android.support.v4.app.ActivityCompat
import android.util.Log
import android.widget.Toast

class FingerPrintHelper(private var context: Context) : FingerprintManager.AuthenticationCallback() {

    private var cancellationSignal: CancellationSignal? = null
    private lateinit var onFingerprintAuthenticatorCallback: FingerprintAuthenticatorCallback

    fun setFingerprintCallback(onFingerprintAuthenticatorCallback: FingerprintAuthenticatorCallback) {
        this.onFingerprintAuthenticatorCallback = onFingerprintAuthenticatorCallback
    }

    fun startAuth(manager: FingerprintManager, cryptoObject: FingerprintManager.CryptoObject) {
        cancellationSignal = CancellationSignal()
        if (ActivityCompat.checkSelfPermission(context,
                Manifest.permission.USE_FINGERPRINT) != PackageManager.PERMISSION_GRANTED) {
            return
        }
        manager.authenticate(cryptoObject, cancellationSignal, 0, this, null)
    }

    fun stopListening() {
        if (cancellationSignal != null) {
            cancellationSignal!!.cancel()
            cancellationSignal = null
        }
    }

    override fun onAuthenticationError(errorCode: Int, errString: CharSequence?) {
        super.onAuthenticationError(errorCode, errString)
        Log.e("FingerprintHelper", "onAuthenticationError : " + errString)
    }

    override fun onAuthenticationHelp(helpCode: Int, helpString: CharSequence?) {
        super.onAuthenticationHelp(helpCode, helpString)
        Toast.makeText(context, "Authentication help\n" + helpString, Toast.LENGTH_LONG).show()
    }

    override fun onAuthenticationSucceeded(result: FingerprintManager.AuthenticationResult?) {
        super.onAuthenticationSucceeded(result)
//        Toast.makeText(context, "Authentication succeeded.", Toast.LENGTH_LONG).show()
        // may use callback to do something
        onFingerprintAuthenticatorCallback.onFingerprintAuthenticationSuccess()
    }

    override fun onAuthenticationFailed() {
        super.onAuthenticationFailed()
//        Toast.makeText(context, "Authentication failed.", Toast.LENGTH_LONG).show()
        onFingerprintAuthenticatorCallback.onFingerprintAuthenticationFailed()
    }


}