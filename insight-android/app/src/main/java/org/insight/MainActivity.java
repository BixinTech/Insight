package org.insight;

import android.app.ActivityManager;
import android.app.AlarmManager;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.provider.Settings;
import android.telephony.TelephonyManager;
import android.util.Pair;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import java.io.File;
import java.io.FileDescriptor;
import java.io.FileInputStream;
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
                "java.io.FileOutputStream $init(java.io.FileDescriptor)",
                () -> {
                    try {
                        FileDescriptor fd = new FileOutputStream(new File("/data/user/0/org.insight/lib-main/dso_state")).getFD();
                        FileOutputStream fileOutputStream = new FileOutputStream(fd);
                    } catch (Exception e) {
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
        testCases.add(new Pair<>(
                "android.app.ContextImpl sendBroadcast()",
                () -> {
                    sendBroadcast(new Intent());
                })
        );
        testCases.add(new Pair<>(
                "java.io.File delete()",
                () -> {
                    new File("").delete();
                })
        );
        testCases.add(new Pair<>(
                "java.io.FileInputStream $init(java.io.File)",
                () -> {
                    try {
                        new FileInputStream(new File("/data/user/0/org.insight/lib-main/dso_state"));
                    } catch (FileNotFoundException e) {
                        e.printStackTrace();
                    }
                })
        );
        testCases.add(new Pair<>(
                "android.app.AlarmManager setImpl()",
                () -> {
                    AlarmManager alarmManager = (AlarmManager) getSystemService(Context.ALARM_SERVICE);
                    alarmManager.setRepeating(AlarmManager.RTC_WAKEUP, System.currentTimeMillis(), 10000, null);
                })
        );
        recyclerView.setAdapter(new TestCaseAdapter(testCases));
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        MenuInflater inflater = getMenuInflater();
        inflater.inflate(R.menu.menu_activity_main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(@NonNull MenuItem item) {
        if (item.getTitle().equals("Scan")) {
            Intent intent = new Intent(this, InsightScanRegisterActivity.class);
            startActivity(intent);
        }
        return super.onOptionsItemSelected(item);
    }
}