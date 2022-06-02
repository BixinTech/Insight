package org.insight;

import android.util.Log;

import androidx.annotation.NonNull;

import java.io.IOException;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.FormBody;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

public class InsightApi {
    private static class Inner {
        private static final InsightApi sInstance = new InsightApi();
    }

    private InsightApi() {

    }

    public static InsightApi getInstance() {
        return Inner.sInstance;
    }

    private final OkHttpClient client = new OkHttpClient();

    public static String SESSION_ID;

    public Call register(String url) throws IOException {
        Request request = new Request.Builder()
                .url(url)
                .build();

        return client.newCall(request);
    }

    public void flush(String url, String signature, String stackTrace) {
        Log.d("Insight", url);
        if (SESSION_ID != null) {
            RequestBody body = new FormBody.Builder()
                    .add("SESSION_ID", SESSION_ID)
                    .add("signature", signature)
                    .add("stackTrace", stackTrace).build();
            Request request = new Request.Builder()
                    .url(url)
                    .post(body)
                    .build();

            client.newCall(request).enqueue(new Callback() {
                @Override
                public void onFailure(@NonNull Call call, @NonNull IOException e) {
                    System.out.println();
                }

                @Override
                public void onResponse(@NonNull Call call, @NonNull Response response) throws IOException {
                    System.out.println();
                }
            });
        }
    }
}
