package org.tvbrowser.utils;

import android.annotation.SuppressLint;
import android.os.Build;
import android.util.Log;

import org.conscrypt.Conscrypt;

import java.net.CookieHandler;
import java.net.CookieManager;
import java.net.CookiePolicy;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * Utility class for network related operations and network security handling.
 */
public final class NetUtils {

    private static final String TAG = "NetUtils";
    private static SSLSocketFactory mOriginalSSLSocketFactory;
    private static HostnameVerifier mOriginalHostnameVerifier;

    private NetUtils() {
    }

    public static void disableCertificateValidation() {
        // Create a trust manager that does not validate certificate chains
        @SuppressLint("CustomX509TrustManager")
        final TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }

                    @SuppressLint("TrustAllX509TrustManager")
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {
                        // ignored intentionally
                    }

                    @SuppressLint("TrustAllX509TrustManager")
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                        // ignored intentionally
                    }
                }};

        // Ignore differences between given hostname and certificate hostname
        final HostnameVerifier hv = (hostname, session) -> hostname.equals(session.getPeerHost());

        // Install the all-trusting trust manager
        try {
            if (mOriginalSSLSocketFactory == null) {
                mOriginalSSLSocketFactory = HttpsURLConnection.getDefaultSSLSocketFactory();
            }
            if (mOriginalHostnameVerifier == null) {
                mOriginalHostnameVerifier = HttpsURLConnection.getDefaultHostnameVerifier();
            }

            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
            HttpsURLConnection.setDefaultHostnameVerifier(hv);
        } catch (Exception e) {
            // ignore
        }
    }

    public static void resetCertificateValidation() {
        if (mOriginalSSLSocketFactory != null) {
            HttpsURLConnection.setDefaultSSLSocketFactory(mOriginalSSLSocketFactory);
        }
        if (mOriginalHostnameVerifier != null) {
            HttpsURLConnection.setDefaultHostnameVerifier(mOriginalHostnameVerifier);
        }
    }

    public static void prepareConnection() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N_MR1) {
            disableCertificateValidation();
        }
    }

    public static void finishConnection() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N_MR1) {
            resetCertificateValidation();
        }
    }

    /**
     * Installs Conscrypt as the first security provider for new SSLContext instances.
     * Conscrypt is a Java port of the OpenSSL library maintained by Google.
     * See <a href="https://conscrypt.org/">https://conscrypt.org/</a> or
     * <a href="https://github.com/google/conscrypt">https://github.com/google/conscrypt</a>
     * for more details.
     * <p>
     * It replaces the default JSSE (Java Secure Socket Extension) provider on old Android versions
     * prior to Android Q (API 29, where Conscrypt often became the default) or for specific needs.
     * <p>
     * Using Conscrypt provides modern TLS features without requiring Google Play Services, which is
     * beneficial for broader device compatibility. The GMS implementation of ProviderInstaller
     * also requires a minimum SDK version of 25, where Conscrypt is backward compatible with SDK 16.
     * <p>
     * This method specifically targets versions older than N_MR1 (Android 7.1.1, API 25)
     * where older TLS implementations might lack support for modern protocols or ciphers
     * required by some servers (e.g., TLS 1.3, certain cipher suites).
     * <p>
     * If the installation fails, the app should inform the user, that the system is insecure or
     * the communication with servers might fail.
     * <p>
     * Note: Conscrypt will not update any outdated certificates (i.e. expired or revoked CAs).
     * Certificates (i.e. PEM files) can be provided as assets and handled by a custom trust manager.
     * </p>
     * <ul>
     *     <li>Independent of Google Play Services (i.e. supports devices with custom roms,
     *      devices with pure AOSP implementations without Google services)</li>
     *     <li>Updatable via Gradle to the latest version with each new build</li>
     *     <li>Backward compatible with older Android versions (minSdk 16)</li>
     *     <li>Supports modern TLS 1.3 features, cipher suites, protocols, and algorithms</li>
     *     <li>Optimized for Android: Uses BoringSSL, the same cryptographic library used in Chrome</li>
     *     <li>Can be used with SSLContext based APIs like HttpsUrlConnection, or OkHttp 3.x</li>
     *     <li>Does not update webviews, or other APIs outside of the current process</li>
     *     <li>Does not update SSLCertificateSocketFactory</li>
     */
    public static void installConscryptIfNeeded() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N_MR1) {
            try {
                // Insert Conscrypt as first security provider for new SSLContext instances.
                Security.insertProviderAt(Conscrypt.newProvider(), 1);
                Log.i(TAG, "Conscrypt provider installed.");
            } catch (Throwable t) { // Catching Throwable to be safe with library interactions
                Log.e(TAG, "Failed to install Conscrypt provider", t);
            }
        }
    }

    public static void installDefaultCookieHandler() {
        CookieHandler.setDefault(new CookieManager(null, CookiePolicy.ACCEPT_ALL));
    }
}