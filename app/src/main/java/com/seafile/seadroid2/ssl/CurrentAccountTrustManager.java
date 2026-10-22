package com.seafile.seadroid2.ssl;

import com.seafile.seadroid2.account.Account;
import com.seafile.seadroid2.account.SupportAccountManager;

import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * Trusts the current account's server the way {@link SSLTrustManager} does (including
 * certificates the user approved), and every other host by the system CAs only.
 * For clients that load from more than one host, like images.
 */
public final class CurrentAccountTrustManager extends X509ExtendedTrustManager {

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        defaultTrustManager().checkClientTrusted(chain, authType);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        defaultTrustManager().checkClientTrusted(chain, authType);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
        defaultTrustManager().checkClientTrusted(chain, authType);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        defaultTrustManager().checkServerTrusted(chain, authType);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        String host = null;
        if (socket instanceof SSLSocket) {
            SSLSession session = ((SSLSocket) socket).getHandshakeSession();
            if (session != null) {
                host = session.getPeerHost();
            }
        }
        trustManagerFor(host).checkServerTrusted(chain, authType);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
        trustManagerFor(engine == null ? null : engine.getPeerHost()).checkServerTrusted(chain, authType);
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        X509TrustManager dft = SSLTrustManager.instance().getDefaultTrustManager();
        return dft != null ? dft.getAcceptedIssuers() : new X509Certificate[0];
    }

    private X509TrustManager trustManagerFor(String host) throws CertificateException {
        Account account = SupportAccountManager.getInstance().getCurrentAccount();
        if (account != null && host != null && host.equalsIgnoreCase(account.getServerDomainName())) {
            return (X509TrustManager) SSLTrustManager.instance().getTrustManagers(account)[0];
        }
        return defaultTrustManager();
    }

    private X509TrustManager defaultTrustManager() throws CertificateException {
        X509TrustManager dft = SSLTrustManager.instance().getDefaultTrustManager();
        if (dft == null) {
            throw new CertificateException("Trust manager not initialized");
        }
        return dft;
    }
}
