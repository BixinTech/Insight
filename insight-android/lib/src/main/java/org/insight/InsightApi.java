package org.insight;

import java.io.IOException;

import okhttp3.Call;
import okhttp3.OkHttpClient;
import okhttp3.Request;

public class InsightApi {
    private static class Inner {
        private static final InsightApi sInstance = new InsightApi();
    }

    private InsightApi() {

    }

    public static InsightApi getInstance() {
        return Inner.sInstance;
    }

    private OkHttpClient client = new OkHttpClient();

    public Call register(String url) throws IOException {
        Request request = new Request.Builder()
                .url(url)
                .build();

        return client.newCall(request);
    }
}
