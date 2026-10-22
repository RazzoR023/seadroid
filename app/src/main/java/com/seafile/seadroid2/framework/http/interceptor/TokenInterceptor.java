package com.seafile.seadroid2.framework.http.interceptor;

import android.text.TextUtils;

import androidx.annotation.NonNull;

import com.seafile.seadroid2.config.Constants;
import com.seafile.seadroid2.framework.http.HttpIO;
import com.seafile.seadroid2.framework.http.HttpManager;

import java.io.IOException;

import okhttp3.Interceptor;
import okhttp3.Request;
import okhttp3.Response;

public class TokenInterceptor implements Interceptor {
    private String authToken = null;
    private String serverHost = null;

    /**
     * user default account token
     *
     */
    public TokenInterceptor() {

    }

    /**
     * user custom account token, only sent to serverHost
     *
     */
    public TokenInterceptor(String authToken, String serverHost) {
        this.authToken = authToken;
        this.serverHost = serverHost;
    }

    @NonNull
    @Override
    public Response intercept(Chain chain) throws IOException {
        Request request = chain.request();
        return chain.proceed(initBuilder(request.newBuilder(), request.url().host()).build());
    }

    private Request.Builder initBuilder(Request.Builder builder, String requestHost) {
//        builder.addHeader("Content-Type", "application/json");
        builder.addHeader("Accept", "application/json");
        builder.addHeader("charset", "utf-8");
        builder.addHeader("timestamp", String.valueOf(System.currentTimeMillis()));
        builder.addHeader("User-Agent", Constants.UA.SEAFILE_ANDROID_UA);

        String token = authToken;
        String host = serverHost;
        if (TextUtils.isEmpty(token)) {
            HttpIO httpIO = HttpManager.getCurrentLoggedHttp();
            if (httpIO != null) {
                token = httpIO.getCurrentToken();
                if (httpIO.getAccount() != null) {
                    host = httpIO.getAccount().getServerDomainName();
                }
            }
        }

        // never hand the token to other hosts, e.g. external images
        if (!TextUtils.isEmpty(host) && !host.equalsIgnoreCase(requestHost)) {
            return builder;
        }

        if (!TextUtils.isEmpty(token)) {
            builder.addHeader("Authorization", "Token " + token);
        }

        return builder;
    }
}
