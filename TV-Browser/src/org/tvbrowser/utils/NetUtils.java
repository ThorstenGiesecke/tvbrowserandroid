package org.tvbrowser.utils;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.res.AssetManager;
import android.os.Build;
import android.util.Log;

import androidx.annotation.NonNull;

import org.conscrypt.Conscrypt;
import org.tvbrowser.tvbrowser.BuildConfig;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;

import java.net.CookieHandler;
import java.net.CookieManager;
import java.net.CookiePolicy;

import java.security.KeyStore;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * Utility class for network related operations and network security handling.
 */
public final class NetUtils {

    private static final String TAG = "NetUtils";

    private static final Pattern RDN_PATTERN = Pattern.compile(
            "([A-Za-z][A-Za-z0-9]*)\\s*=\\s*(?:\"((?:[^\"]|\"\")*)\"|([^,]*))");

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
                Provider provider = Security.getProvider("Conscrypt");
                if (Conscrypt.isConscrypt(provider)) {
                    Log.i(TAG, "Conscrypt provider already installed.");
                    return;
                }

                // Insert Conscrypt as first security provider for new SSLContext instances.
                provider = Conscrypt.newProvider();
                Security.insertProviderAt(provider, 1);
                Log.i(TAG, "Conscrypt provider installed.");
                if (BuildConfig.DEBUG) {
                    dumpProviderInfo(provider);
                }
            } catch (Throwable t) { // Catching Throwable to be safe with library interactions
                Log.e(TAG, "Failed to install Conscrypt provider", t);
            }
        }
    }

    private static void dumpProviderInfo(@NonNull final Provider provider) {
        Log.d(TAG, "Provider: " + provider.getName() + " " + provider.getVersion());
        for (Provider.Service service : provider.getServices()) {
            Log.d(TAG, "Service: Type " + service.getType() + "; Name: " +
                    service.getAlgorithm() + "; Class: " + service.getClassName());
        }
    }

    public static void installDefaultCookieHandler() {
        CookieHandler.setDefault(new CookieManager(null, CookiePolicy.ACCEPT_ALL));
    }

    /**
     * Installs a Let's Encrypt enabled SSLContext as DefaultSSLSocketFactory into
     * HttpsURLConnection on devices prior to Android N MR1 (API 25).
     */
    public static void installLetsEncryptCaIfNeeded(@NonNull final Context context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N_MR1) {
            try {
                final TrustManagerFactory factory = getTrustManagerFactory(context);
                final SSLContext sslContext = SSLContext.getInstance("TLS");
                sslContext.init(null, factory.getTrustManagers(), new SecureRandom());
                HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
            } catch (Throwable t) {
                Log.e(TAG, "Failed to install Let's Encrypt enabled SSLContext", t);
            }
        }
    }

    /**
     * Returns a TrustManagerFactory that trusts the CAs installed on device and CAs provided
     * by the app via assets/ca (X.509 certificates ending with .pem).
     * <p>
     * To add additional trusted certificates the app can add them to assets/ca (build time).
     */
    public static TrustManagerFactory getTrustManagerFactory(@NonNull Context context)
        throws Exception {

        final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, null);

        final AssetManager assetManager = context.getApplicationContext().getAssets();

        final CertificateFactory cf = CertificateFactory.getInstance("X.509");
        for (final String asset : getPemFilenamesFromAssets(assetManager)) {
            final Certificate certificate = loadCertificateFromAssets(assetManager, asset, cf);
            if (certificate instanceof X509Certificate) {
                final String alias = getIssuerDescriptiveName((X509Certificate)certificate);
                keyStore.setCertificateEntry(alias, certificate);
                Log.d(TAG, "Added X.509 certificate from assets/ca: " + alias);
            }
        }

        // TrustManagerFactory that trusts the CAs installed on device.
        final TrustManagerFactory deviceTrustManagerFactory = TrustManagerFactory.getInstance(
              TrustManagerFactory.getDefaultAlgorithm());
        deviceTrustManagerFactory.init((KeyStore) null);

        for (final TrustManager trustManager : deviceTrustManagerFactory.getTrustManagers()) {
            if (trustManager instanceof X509TrustManager) {
                final X509TrustManager x509TrustManager = (X509TrustManager) trustManager;
                for (final X509Certificate certificate : x509TrustManager.getAcceptedIssuers()) {
                    final String alias = getIssuerDescriptiveName(certificate);
                    keyStore.setCertificateEntry(alias, certificate);
                    Log.d(TAG, "Added X.509 accepted issuer certificate from device: " + alias);
                }
                // TrustManagerFactory that trusts the app provided and default device CAs.
                final TrustManagerFactory customTrustManagerFactory =
                      TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                customTrustManagerFactory.init(keyStore);
                return customTrustManagerFactory;
            }
        }
        throw new IllegalStateException("No X509TrustManager found in getTrustManagerFactory");
    }

    public static Certificate loadCertificateFromAssets(
            @NonNull final AssetManager assetManager, @NonNull final String asset,
            @NonNull final CertificateFactory cf) throws IOException, CertificateException {
        final Certificate ca;
        try (final InputStream inputStream = new BufferedInputStream(assetManager.open(asset))) {
            try {
                ca = cf.generateCertificate(inputStream);
            } finally {
                inputStream.close();
            }
        }
        return ca;
    }

    public static String[] getPemFilenamesFromAssets(@NonNull final AssetManager assetManager) {
        final List<String> pemFilesList = new ArrayList<>();
        try {
            final String[] assetsInCaDir = assetManager.list("ca");
            if (assetsInCaDir != null) {
                for (final String assetName : assetsInCaDir) {
                    if (assetName.endsWith(".pem")) {
                       final  String fullAssetPath = "ca/" + assetName;
                        boolean isLikelyFile = false;
                        try (InputStream is = assetManager.open(fullAssetPath)) {
                            isLikelyFile = true;
                        } catch (IOException ignore) {}

                        if (isLikelyFile) {
                            pemFilesList.add(fullAssetPath);
                        }
                    }
                }
            }
        } catch (IOException ignore) {}
        return pemFilesList.toArray(new String[0]);
    }

    /**
     * Extracts a descriptive name from the certificate's Issuer Distinguished Name.
     * It tries to find the Common Name (CN). If not found, it tries to find the
     * first Organizational Unit (OU). If neither is found, it returns the full
     * Issuer DN string.
     *
     * @param certificate The X509Certificate from which to extract the issuer name.
     * @return The extracted CN, or OU, or the full Issuer DN string.
     */
    public static String getIssuerDescriptiveName(@NonNull final X509Certificate certificate) {

        final String issuerDnString = certificate.getIssuerX500Principal().getName();

        String cn = null;
        String ou = null;

        final Matcher matcher = RDN_PATTERN.matcher(issuerDnString);
        while (matcher.find()) {
            final String rdnType = matcher.group(1).toUpperCase();
            // Handles quoted and unquoted values
            final String rdnValue = matcher.group(2) != null ? matcher.group(2)
                    .replace("\"\"", "\"") : matcher.group(3).trim();
            if ("CN".equals(rdnType)) {
                cn = rdnValue;
                break;
            } else if ("OU".equals(rdnType) && ou == null) {
                // Capture the first OU we find, in case CN is not present
                ou = rdnValue;
            }
        }

        if (cn != null && !cn.isEmpty()) {
            return cn;
        } else if (ou != null && !ou.isEmpty()) {
            return ou;
        } else {
            return issuerDnString; // Fallback to the full DN string
        }
    }
}