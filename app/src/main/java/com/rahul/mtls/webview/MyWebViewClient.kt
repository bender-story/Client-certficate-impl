package com.rahul.mtls.webview

import android.app.Activity
import android.webkit.WebView

import android.graphics.Bitmap
import android.util.Log

import android.webkit.ClientCertRequest

import android.webkit.WebViewClient
import java.io.InputStream
import java.lang.Exception
import java.security.Key
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import java.util.*


class MyWebViewClient(val activity: Activity, var rawID: Int) : WebViewClient() {

    private var mPrivateKey : PrivateKey? = null
    var  mCertificates : Array<X509Certificate?>? = arrayOfNulls(1)

    private fun getClientCertData() {
        val keyStore: KeyStore = KeyStore.getInstance("PKCS12", "BC")
        val inputStream: InputStream = activity.resources.openRawResource(rawID)
        inputStream.use { it ->
            keyStore.load(it, "badssl.com".toCharArray())
        }


        val entity = keyStore.getEntry("X", null) as KeyStore.PrivateKeyEntry?
        mPrivateKey = entity?.privateKey
        mCertificates = entity?.certificateChain as Array<X509Certificate?>?

    }

    private fun loadCertificateAndPrivateKey() {
        try {
//            val certificateFileStream = javaClass.getResourceAsStream("/assets/cert.pfx")
            val inputStream: InputStream = activity.resources.openRawResource(rawID)
            val keyStore = KeyStore.getInstance("PKCS12", "BC")
            val password = "badssl.com"
            keyStore.load(
                inputStream,
                if (password != null) password.toCharArray() else null
            )
            val aliases: Enumeration<String> = keyStore.aliases()
            val alias: String = aliases.nextElement()
            val key: Key = keyStore.getKey(alias, password.toCharArray())
            if (key is PrivateKey) {
                mPrivateKey = key
                val cert: Certificate = keyStore.getCertificate(alias)
                mCertificates?.set(0, cert as X509Certificate )
            }
            inputStream.close()
        } catch (e: Exception) {
            Log.e("sample", e.toString())
        }
    }



    override fun onReceivedClientCertRequest(view: WebView, request: ClientCertRequest) {
        //HERE YOU CAN DO SOME STUFF TO RETRIEVE KEY AND CERTIFICATES
        if (mCertificates == null || mPrivateKey == null) {
            loadCertificateAndPrivateKey()
        }
        request.proceed(mPrivateKey, mCertificates)
    }

    override fun onReceivedError(
        view: WebView, errorCode: Int,
        description: String, failingUrl: String
    ) {
        super.onReceivedError(
            view, errorCode,
            description, failingUrl
        )
    }

    override fun onPageStarted(view: WebView, url: String, favicon: Bitmap?) {
        super.onPageStarted(view, url, favicon)
    }

    override fun shouldOverrideUrlLoading(view: WebView, url: String): Boolean {
        view.loadUrl(url)
        return true
    }
}