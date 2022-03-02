package com.rahul.mtls.webview

import android.annotation.SuppressLint
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import com.rahul.mtls.R
import android.view.View

import android.webkit.WebView

class WebViewActivity : AppCompatActivity() {
    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_web_view)

        var webview = findViewById<View>(R.id.myWebView) as WebView
        webview.webViewClient = MyWebViewClient(this, R.raw.client)
        webview.settings.javaScriptEnabled = true
        webview.loadUrl("https://client.badssl.com")
    }
}