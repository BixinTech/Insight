package org.insight;

import android.Manifest;
import android.annotation.SuppressLint;
import android.content.Context;
import android.content.pm.PackageManager;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.Bundle;
import android.text.format.Formatter;
import android.util.DisplayMetrics;
import android.util.Log;
import android.view.View;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import androidx.camera.core.AspectRatio;
import androidx.camera.core.CameraSelector;
import androidx.camera.core.ImageAnalysis;
import androidx.camera.core.ImageProxy;
import androidx.camera.core.Preview;
import androidx.camera.lifecycle.ProcessCameraProvider;
import androidx.camera.view.PreviewView;
import androidx.core.content.ContextCompat;

import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONObject;
import com.google.android.material.progressindicator.CircularProgressIndicator;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.mlkit.vision.barcode.BarcodeScanner;
import com.google.mlkit.vision.barcode.BarcodeScanning;
import com.google.mlkit.vision.barcode.common.Barcode;
import com.google.mlkit.vision.common.InputImage;

import java.io.IOException;
import java.util.Objects;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;

public class InsightScanRegisterActivity extends AppCompatActivity {

    private static final int PERMISSION_CAMERA_REQUEST = 1;
    private static final double RATIO_4_3_VALUE = 4.0 / 3.0;
    private static final double RATIO_16_9_VALUE = 16.0 / 9.0;

    private PreviewView previewView;
    private CircularProgressIndicator circularProgressIndicator;

    private ProcessCameraProvider cameraProvider;
    private CameraSelector cameraSelector;
    private Preview preview;
    private ImageAnalysis imageAnalysis;

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        setContentView(R.layout.activity_scan_register);

        previewView = findViewById(R.id.preview_view);
        circularProgressIndicator = findViewById(R.id.circular_progress_indicator);

        setupCamera();
    }

    private void setupCamera() {
        cameraSelector = new CameraSelector.Builder().requireLensFacing(CameraSelector.LENS_FACING_BACK).build();

        ListenableFuture<ProcessCameraProvider> cameraProviderFuture = ProcessCameraProvider.getInstance(this);
        cameraProviderFuture.addListener(() -> {
            try {
                cameraProvider = cameraProviderFuture.get();
                if (isCameraPermissionGranted()) {
                    bindCameraUseCases();
                } else {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                        requestPermissions(
                                new String[]{Manifest.permission.CAMERA},
                                PERMISSION_CAMERA_REQUEST
                        );
                    }
                }
            } catch (ExecutionException | InterruptedException e) {
                // Handle any errors (including cancellation) here.
                Log.e("QrScanViewModel", "Unhandled exception", e);
            }
        }, ContextCompat.getMainExecutor(this));
    }

    private void bindCameraUseCases() {
        bindPreviewUseCase();
        bindAnalyseUseCase();
    }

    private void bindPreviewUseCase() {
        if (cameraProvider == null) {
            return;
        }
        if (preview != null) {
            cameraProvider.unbind(preview);
        }

        preview = new Preview.Builder()
                .setTargetAspectRatio(getScreenAspectRatio())
                .setTargetRotation(previewView.getDisplay().getRotation())
                .build();

        preview.setSurfaceProvider(previewView.getSurfaceProvider());

        try {
            cameraProvider.bindToLifecycle(this, cameraSelector, preview);
        } catch (IllegalStateException | IllegalArgumentException e) {
            // Handle any errors (including cancellation) here.
            Log.e("BindToLifecycle", "Unhandled exception", e);
        }
    }

    private void bindAnalyseUseCase() {
        BarcodeScanner barcodeScanner = BarcodeScanning.getClient();

        if (cameraProvider == null) {
            return;
        }
        if (imageAnalysis != null) {
            cameraProvider.unbind(imageAnalysis);
        }

        imageAnalysis = new ImageAnalysis.Builder()
                .setTargetAspectRatio(getScreenAspectRatio())
                .setTargetRotation(previewView.getDisplay().getRotation())
                .build();

        // Initialize our background executor
        ExecutorService cameraExecutor = Executors.newSingleThreadExecutor();

        imageAnalysis.setAnalyzer(cameraExecutor, imageProxy -> processImageProxy(barcodeScanner, imageProxy));

        try {
            cameraProvider.bindToLifecycle(/* lifecycleOwner= */this,
                    cameraSelector, imageAnalysis
            );
        } catch (IllegalStateException | IllegalArgumentException e) {
            // Handle any errors (including cancellation) here.
            Log.e("BindToLifecycle", "Unhandled exception", e);
        }
    }

    private boolean requesting = false;

    @SuppressLint("UnsafeOptInUsageError")
    private void processImageProxy(
            BarcodeScanner barcodeScanner,
            ImageProxy imageProxy
    ) {
        if (imageProxy.getImage() == null) return;
        InputImage inputImage =
                InputImage.fromMediaImage(imageProxy.getImage(), imageProxy.getImageInfo().getRotationDegrees());

        barcodeScanner.process(inputImage)
                .addOnSuccessListener(barcodes -> {
                    if (barcodes.size() > 0) {
                        Barcode barcode = barcodes.get(0);

                        if (requesting) {
                        } else {
                            requesting = true;
                            runOnUiThread(() -> {
                                circularProgressIndicator.setVisibility(View.VISIBLE);
                            });

                            String registerUrl = barcode.getRawValue();
                            Context context = InsightScanRegisterActivity.this.getApplicationContext();
                            WifiManager wm = (WifiManager) context.getSystemService(Context.WIFI_SERVICE);
                            String ip = Formatter.formatIpAddress(wm.getConnectionInfo().getIpAddress());
                            try {
                                InsightApi.getInstance().register(registerUrl + "?ip=" + ip).enqueue(new Callback() {
                                    @Override
                                    public void onFailure(@NonNull Call call, @NonNull IOException e) {
                                        requesting = false;
                                        runOnUiThread(() -> {
                                            circularProgressIndicator.setVisibility(View.GONE);
                                        });
                                    }

                                    @Override
                                    public void onResponse(@NonNull Call call, @NonNull Response response) throws IOException {

                                        if (response.isSuccessful()) {
                                            String responseString = Objects.requireNonNull(response.body()).string();
                                            // Do what you want to do with the response.
                                            System.out.println();

                                            JSONObject jsonObject = (JSONObject) JSON.parse(responseString);
                                            int code = jsonObject.getInteger("code");
                                            JSONObject data = jsonObject.getJSONObject("data");
                                            String message = jsonObject.getString("message");

                                            runOnUiThread(() -> {
                                                Toast.makeText(InsightScanRegisterActivity.this, message, Toast.LENGTH_LONG).show();
                                                finish();
                                            });
                                        } else {
                                            // Request not successful
                                        }

                                        requesting = false;
                                        runOnUiThread(() -> {
                                            circularProgressIndicator.setVisibility(View.GONE);
                                        });
                                    }
                                });
                            } catch (IOException e) {
                                e.printStackTrace();
                            }
                        }
                    }
                })
                .addOnCompleteListener(task -> imageProxy.close());
    }

    private boolean isCameraPermissionGranted() {
        return ContextCompat.checkSelfPermission(InsightScanRegisterActivity.this, Manifest.permission.CAMERA)
                == PackageManager.PERMISSION_GRANTED;
    }

    private int getScreenAspectRatio() {
        DisplayMetrics displayMetrics = new DisplayMetrics();
        previewView.getDisplay().getRealMetrics(displayMetrics);
        return aspectRatio(displayMetrics.widthPixels, displayMetrics.heightPixels);
    }

    private int aspectRatio(int width, int height) {
        double previewRatio = ((double) Math.max(width, height)) / ((double) Math.min(width, height));
        if (Math.abs(previewRatio - RATIO_4_3_VALUE) <= Math.abs(previewRatio - RATIO_16_9_VALUE)) {
            return AspectRatio.RATIO_4_3;
        }
        return AspectRatio.RATIO_16_9;
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        if (requestCode == PERMISSION_CAMERA_REQUEST) {
            if (isCameraPermissionGranted()) {
                setupCamera();
            }
        }

        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
    }
}
