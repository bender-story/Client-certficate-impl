package com.rahul.mtls

import android.content.Intent
import android.net.Uri
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.webkit.WebView
import android.widget.Button
import androidx.browser.customtabs.CustomTabsIntent
import com.rahul.mtls.webview.WebViewActivity
import java.io.InputStream
import java.lang.Exception
import java.security.KeyStore
import javax.net.ssl.*
import java.net.HttpURLConnection
import java.net.URL
import android.security.KeyChain
import android.util.Log
import android.util.Log.DEBUG
import com.rahul.mtls.BuildConfig.DEBUG
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.Security
import java.security.cert.Certificate
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.*


class MainActivity : AppCompatActivity() {
    var buttonInAppBrowser: Button? = null
    var buttonWebView: Button? = null
    var buttonHttpCallWithCert: Button? = null
    var buttonHttpCallNoCert: Button? = null
    var webView: WebView? = null
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        buttonInAppBrowser = findViewById<Button>(R.id.goThere)
        buttonWebView = findViewById<Button>(R.id.goThereWebView)
        buttonHttpCallWithCert = findViewById<Button>(R.id.fetchData)
        buttonHttpCallNoCert = findViewById<Button>(R.id.fetchDataWithoutCert)
        webView = findViewById(R.id.httpText)
    }

    override fun onResume() {
        super.onResume()
//        addCert()
        buttonInAppBrowser?.setOnClickListener {
            if(isCertificateInstalled("C=US,ST=California,L=San Francisco,O=BadSSL,CN=BadSSL Client Root Certificate Authority")) openBrowser()
           else addCertInKeyStore()

        }

        buttonWebView?.setOnClickListener {
            startActivity(Intent(this, WebViewActivity::class.java))
        }

        buttonHttpCallWithCert?.setOnClickListener {
            val runnable = Runnable {
                getHTTPData()
            }
            Thread(runnable).start()
        }

        buttonHttpCallNoCert?.setOnClickListener {
            val runnable = Runnable {
                getHTTPData(false)
            }
            Thread(runnable).start()
        }
    }

    private fun openBrowser(){
                    val customTab = CustomTabsIntent.Builder().build()
            val intent = customTab.intent
            intent.data = Uri.parse("https://client.badssl.com")
            customTab.intent.data?.let { it -> customTab.launchUrl(this, it) }
    }

    private fun addCertInKeyStore(){
//        val keyStore: KeyStore = KeyStore.getInstance("PKCS12", "BC")
        val inputStream: InputStream = resources.openRawResource(R.raw.client)
        val intent = KeyChain.createInstallIntent()
        val p12: ByteArray = inputStream.readBytes()
        intent.putExtra(KeyChain.EXTRA_PKCS12, p12)
        intent.putExtra(KeyChain.EXTRA_NAME, "Sample cert")
        startActivityForResult(intent,3)
    }
//    private fun addCertInKeyStore2(){
//        val keyStore: KeyStore = KeyStore.getInstance("PKCS12")
//        val inputStream: InputStream = resources.openRawResource(R.raw.client)
//        inputStream.use { it ->
//            keyStore.load(it, "badssl.com".toCharArray())
//        }
//        val aliases = keyStore.aliases()
//        var cert:X509Certificate? = null
//        while (aliases.hasMoreElements()) {
//            val alias = aliases.nextElement()
//             cert = keyStore.getCertificate(alias) as X509Certificate
//            Log.d(
//                "cert -->", "Subject DN: " +
//                        cert.getSubjectDN().getName()
//            )
//            Log.d(
//                "cert -->", "Issuer DN: " +
//                        cert.getIssuerDN().getName()
//            )
//        }
//
//
//        val intent = KeyChain.createInstallIntent()
////        val p12: ByteArray = inputStream.readBytes()
//        intent.putExtra(KeyChain.EXTRA_CERTIFICATE, cert?.encoded)
//        intent.putExtra(KeyChain.EXTRA_NAME, "Sample cert")
//        startActivityForResult(intent,3)
//    }

    private fun getClientCertData(): SSLContext? {
        val keyStore: KeyStore = KeyStore.getInstance("PKCS12", "BC")
        val inputStream: InputStream = resources.openRawResource(R.raw.client)
        inputStream.use { it ->
            keyStore.load(it, "badssl.com".toCharArray())
        }

        val kmf = KeyManagerFactory.getInstance("X509")
        kmf.init(keyStore, "badssl.com".toCharArray())
        val keyManagers: Array<KeyManager> = kmf.keyManagers
        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(keyManagers, null, null)
        return sslContext
    }


    private fun getHTTPData(cert:Boolean = true) {
        var result: String? = null
        var urlConnection: HttpURLConnection? = null
        try {
            val requestedUrl = URL("https://client.badssl.com")
            urlConnection = requestedUrl.openConnection() as HttpURLConnection
            if (urlConnection is HttpsURLConnection) {
              if(cert)  urlConnection.sslSocketFactory = getClientCertData()?.socketFactory
            }
            urlConnection.requestMethod = "GET"
            urlConnection.connectTimeout = 1500
            urlConnection.readTimeout = 1500
            val lastResponseCode = urlConnection.responseCode
            result = urlConnection.inputStream.bufferedReader().use { it.readText() }
            val lastContentType = urlConnection.contentType
        } catch (ex: Exception) {
            result = ex.toString()
        } finally {
            urlConnection?.disconnect()
        }

        loadHTML(result?:"")
    }

    private fun loadHTML(result: String) {
        runOnUiThread {
//            webView?.setText(Html.fromHtml(result));
            webView?.loadData(result, "text/html", "UTF-8");
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {

        if(requestCode == 3 && resultCode == RESULT_OK){
            openBrowser()
        } else  super.onActivityResult(requestCode, resultCode, data)
    }

    private fun isCertificateInstalled(issuerDn: String): Boolean {
            try {
                val ks = KeyStore.getInstance("AndroidCAStore")
                if (ks != null) {
                    ks.load(null, null)
                    val aliases = ks.aliases()
                    while (aliases.hasMoreElements()) {
                        val alias = aliases.nextElement() as String
                        val cert = ks.getCertificate(alias) as X509Certificate
                        Log.d("Cert ---->",cert.issuerDN.name)
                        if (cert.issuerDN.name.contains(issuerDn)) {
                            return true
                        }
                    }
                }
            } catch (e: IOException) {
                e.printStackTrace()
            } catch (e: KeyStoreException) {
                e.printStackTrace()
            } catch (e: NoSuchAlgorithmException) {
                e.printStackTrace()
            } catch (e: CertificateException) {
                e.printStackTrace()
            }
            return false
    }

//    private fun addCert() {
//        val keyStore: KeyStore = KeyStore.getInstance("PKCS12", "BC")
//        val inputStream: InputStream = resources.openRawResource(R.raw.client)
//        inputStream.use { it ->
//            keyStore.load(it, "badssl.com".toCharArray())
//        }
////        val reader = BufferedReader(inputStream.reader())
//
//        val kmf: KeyManagerFactory = KeyManagerFactory.getInstance("X509") //x509
//
//
////        val content = StringBuilder()
////        try {
////            var line = reader.readLine()
////            while (line != null) {
////                content.append(line)
////                line = reader.readLine()
////            }
////        } finally {
////            reader.close()
////        }
////        val sb = StringBuilder()
////        var ch: Int
////            while (inputStream.read().also { ch = it } != -1) {
////                sb.append(ch.toChar())
////            }
//
//        kmf.init(keyStore, "badssl.com".toCharArray())
//
//        val sslContext = SSLContext.getInstance("TLSv1.2") //TLSv1.2
//
//        sslContext.init(kmf.keyManagers, null, null)
//
//        HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.socketFactory)
////        SslCertificateAuthority.setCustomCertificateAuthority(inputStream)
////        val defaultCAs: KeyStore = KeyStore.getInstance("AndroidCAStore")
////        if (defaultCAs != null) {
////            defaultCAs.load(null, null)
////            val keyAliases: Enumeration<String> = defaultCAs.aliases()
////            while (keyAliases.hasMoreElements()) {
////                val alias: String = keyAliases.nextElement()
////                val cert: Certificate = defaultCAs.getCertificate(alias)
////                try {
////                    if (!keyStore.containsAlias(alias)) keyStore.setCertificateEntry(alias, cert)
////                } catch (e: Exception) {
////                    println("Error adding $e")
////                }
////            }
////        }
////        val tmf: TrustManagerFactory =
////            TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
////        tmf.init(keyStore)
////// Get a new SSL context
////// Get a new SSL context
////        val ctx: SSLContext = SSLContext.getInstance("SSL")
////        ctx.init(null, tmf.getTrustManagers(), SecureRandom())
////        return ctx.getSocketFactory()
//    }


}