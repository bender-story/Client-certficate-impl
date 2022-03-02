package com.rahul.mtls

import java.io.BufferedInputStream
import java.io.IOException
import java.io.InputStream
import java.net.MalformedURLException
import java.security.KeyManagementException
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.cert.Certificate
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.*
import javax.net.ssl.*

object SslCertificateAuthority {
    fun setCustomCertificateAuthority(inputStream: InputStream?) {
        try {
            // Load CAs from an InputStream
            // (could be from a resource or ByteArrayInputStream or ...)
            val cf: CertificateFactory = CertificateFactory.getInstance("X.509")
            val caInput: InputStream = BufferedInputStream(inputStream)
            val ca: Certificate
            try {
                ca = cf.generateCertificate(caInput) as X509Certificate
                System.out.println("ca=" + (ca as X509Certificate).getSubjectDN())
            } finally {
                caInput.close()
            }

            // Create a KeyStore containing our trusted CAs
            val keyStoreType: String = KeyStore.getDefaultType()
            val keyStore: KeyStore = KeyStore.getInstance(keyStoreType)
            keyStore.load(null, null)
            keyStore.setCertificateEntry("ca", ca)

            // Create a TrustManager that trusts the CAs in our KeyStore and system CA
            val trustManager = UnifiedTrustManager(keyStore)

            // Create an SSLContext that uses our TrustManager
            val context: SSLContext = SSLContext.getInstance("TLS")
            context.init(null, arrayOf(trustManager), null)

            // Tell the URLConnection to use a SocketFactory from our SSLContext
            HttpsURLConnection.setDefaultSSLSocketFactory(context.getSocketFactory())
        } catch (e: CertificateException) {
            e.printStackTrace()
        } catch (e: NoSuchAlgorithmException) {
            e.printStackTrace()
        } catch (e: KeyStoreException) {
            e.printStackTrace()
        } catch (e: KeyManagementException) {
            e.printStackTrace()
        } catch (e: MalformedURLException) {
            e.printStackTrace()
        } catch (e: IOException) {
            e.printStackTrace()
        }
    }

    private class UnifiedTrustManager(localKeyStore: KeyStore?) :
        X509TrustManager {
        private var defaultTrustManager: X509TrustManager? = null
        private var localTrustManager: X509TrustManager? = null
        @Throws(NoSuchAlgorithmException::class, KeyStoreException::class)
        private fun createTrustManager(store: KeyStore?): X509TrustManager {
            val tmfAlgorithm: String = TrustManagerFactory.getDefaultAlgorithm()
            val tmf: TrustManagerFactory = TrustManagerFactory.getInstance(tmfAlgorithm)
            tmf.init(store as KeyStore?)
            val trustManagers: Array<TrustManager> = tmf.getTrustManagers()
            return trustManagers[0] as X509TrustManager
        }

        @Throws(CertificateException::class)
        override fun checkServerTrusted(chain: Array<X509Certificate?>?, authType: String?) {
            try {
                defaultTrustManager?.checkServerTrusted(chain, authType)
            } catch (ce: CertificateException) {
                localTrustManager?.checkServerTrusted(chain, authType)
            }
        }

        override fun getAcceptedIssuers(): Array<X509Certificate> {
            val first: Array<X509Certificate> = defaultTrustManager?.getAcceptedIssuers() as Array<X509Certificate>
            val second: Array<X509Certificate> = localTrustManager?.getAcceptedIssuers() as Array<X509Certificate>
            val result: Array<X509Certificate> = Arrays.copyOf(first, first.size + second.size)
            System.arraycopy(second, 0, result, first.size, second.size)
            return result
        }

        @Throws(CertificateException::class)
        override fun checkClientTrusted(chain: Array<X509Certificate?>?, authType: String?) {
            try {
                defaultTrustManager?.checkClientTrusted(chain, authType)
            } catch (ce: CertificateException) {
                localTrustManager?.checkClientTrusted(chain, authType)
            }
        }

//        val acceptedIssuers: Array<X509Certificate>
//            get() {
//                val first: Array<X509Certificate> = defaultTrustManager.getAcceptedIssuers()
//                val second: Array<X509Certificate> = localTrustManager.getAcceptedIssuers()
//                val result: Array<X509Certificate> = Arrays.copyOf(first, first.size + second.size)
//                System.arraycopy(second, 0, result, first.size, second.size)
//                return result
//            }

        init {
            try {
                defaultTrustManager = createTrustManager(null)
                localTrustManager = createTrustManager(localKeyStore)
            } catch (e: NoSuchAlgorithmException) {
                e.printStackTrace()
            }
        }
    }
}