package org.insight;

import android.Manifest;
import android.annotation.SuppressLint;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.util.DisplayMetrics;
import android.util.Log;
import android.widget.TextView;

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

import com.google.common.util.concurrent.ListenableFuture;
import com.google.mlkit.vision.barcode.BarcodeScanner;
import com.google.mlkit.vision.barcode.BarcodeScanning;
import com.google.mlkit.vision.barcode.common.Barcode;
import com.google.mlkit.vision.common.InputImage;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class InsightScanRegisterActivity extends AppCompatActivity {

    private static final int PERMISSION_CAMERA_REQUEST = 1;
    private static final double RATIO_4_3_VALUE = 4.0 / 3.0;
    private static final double RATIO_16_9_VALUE = 16.0 / 9.0;

    private PreviewView pvScan;
    private TextView scanResultTextView;
    private ProcessCameraProvider cameraProvider;
    private CameraSelector cameraSelector;
    private Preview previewUseCase;
    private ImageAnalysis analysisUseCase;

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        setContentView(R.layout.activity_scan_register);

        scanResultTextView = findViewById(R.id.scanResultTextView);
        pvScan = findViewById(R.id.scanPreview);

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
        if (previewUseCase != null) {
            cameraProvider.unbind(previewUseCase);
        }

        previewUseCase = new Preview.Builder()
                .setTargetAspectRatio(getScreenAspectRatio())
                .setTargetRotation(pvScan.getDisplay().getRotation())
                .build();

        previewUseCase.setSurfaceProvider(pvScan.getSurfaceProvider());

        try {
            cameraProvider.bindToLifecycle(this, cameraSelector, previewUseCase);
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
        if (analysisUseCase != null) {
            cameraProvider.unbind(analysisUseCase);
        }

        analysisUseCase = new ImageAnalysis.Builder()
                .setTargetAspectRatio(getScreenAspectRatio())
                .setTargetRotation(pvScan.getDisplay().getRotation())
                .build();

        // Initialize our background executor
        ExecutorService cameraExecutor = Executors.newSingleThreadExecutor();

        analysisUseCase.setAnalyzer(cameraExecutor, imageProxy -> processImageProxy(barcodeScanner, imageProxy));

        try {
            cameraProvider.bindToLifecycle(/* lifecycleOwner= */this,
                    cameraSelector, analysisUseCase
            );
        } catch (IllegalStateException | IllegalArgumentException e) {
            // Handle any errors (including cancellation) here.
            Log.e("BindToLifecycle", "Unhandled exception", e);
        }
    }

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
                        scanResultTextView.setText(barcode.getRawValue());
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
        pvScan.getDisplay().getRealMetrics(displayMetrics);
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
