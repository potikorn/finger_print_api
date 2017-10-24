package com.example.potikorn.fingerprint

interface FingerprintAuthenticatorCallback {

    fun onFingerprintAuthenticationSuccess()
    fun onFingerprintAuthenticationFailed()

}