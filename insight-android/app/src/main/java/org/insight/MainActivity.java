package org.insight;

import android.app.ActivityManager;
import android.content.Context;
import android.os.Bundle;
import android.provider.Settings;
import android.telephony.TelephonyManager;
import android.util.Pair;

import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.RandomAccessFile;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.List;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        RecyclerView recyclerView = findViewById(R.id.cases_rv);
        recyclerView.setLayoutManager(new LinearLayoutManager(this));

        List<Pair<String, Runnable>> testCases = new ArrayList<>();
        testCases.add(new Pair<>(
                "java.io.RandomAccessFile $init(java.io.File, java.lang.String)",
                () -> {
                    try {
                        new RandomAccessFile(new File("/data/user/0/org.insight/lib-main/dso_state"), "r");
                    } catch (FileNotFoundException e) {
                        e.printStackTrace();
                    }
                })
        );
        testCases.add(new Pair<>(
                "java.io.RandomAccessFile $init(java.lang.String, java.lang.String)",
                () -> {
                    try {
                        new RandomAccessFile("/data/user/0/org.insight/lib-main/dso_state", "r");
                    } catch (FileNotFoundException e) {
                        e.printStackTrace();
                    }
                })
        );
        testCases.add(new Pair<>(
                "android.app.ActivityManager getRunningAppProcesses()",
                () -> {
                    ActivityManager activityManager = (ActivityManager) getSystemService(Context.ACTIVITY_SERVICE);
                    activityManager.getRunningAppProcesses();
                })
        );
        testCases.add(new Pair<>(
                "java.net.NetworkInterface getHardwareAddress()",
                () -> {
                    try {
                        NetworkInterface.getNetworkInterfaces().nextElement().getHardwareAddress();
                    } catch (SocketException e) {
                        e.printStackTrace();
                    }
                })
        );
        testCases.add(new Pair<>(
                "java.io.FileOutputStream $init(java.io.File)",
                () -> {
                    try {
                        new FileOutputStream(new File("/data/user/0/org.insight/lib-main/dso_state"));
                    } catch (FileNotFoundException e) {
                        e.printStackTrace();
                    }
                })
        );
        testCases.add(new Pair<>(
                "android.provider.Settings$Secure getStringForUser()",
                () -> {
                    Settings.System.getString(getContentResolver(), Settings.System.ANDROID_ID);
                })
        );
        testCases.add(new Pair<>(
                "android.os.SystemProperties get()",
                () -> {
                    TelephonyManager telephonyManager = (TelephonyManager) getSystemService(Context.TELEPHONY_SERVICE);
                    telephonyManager.getSimOperator();
                })
        );
        recyclerView.setAdapter(new TestCaseAdapter(testCases));
    }
}