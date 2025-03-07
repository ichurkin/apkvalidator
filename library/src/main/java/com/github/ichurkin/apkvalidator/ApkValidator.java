/*
 * Copyright (C) 2011-2019 Ivan Churkin
 *
 */
package com.github.ichurkin.apkvalidator;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.app.AlertDialog;
import android.app.Application;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.PackageManager.NameNotFoundException;
import android.content.pm.Signature;
import android.content.res.Resources;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.text.format.DateUtils;
import android.util.Log;
import android.widget.Toast;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileReader;
import java.io.UnsupportedEncodingException;
import java.lang.ref.SoftReference;
import java.lang.reflect.Field;
import java.net.URLEncoder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Locale;
import java.util.Random;

public abstract class ApkValidator {

    private static final String NO_EMAIL_CLIENT_FOUND = "ic_no_email_client_found";
    private static final String INTEGRITY_EMULATOR_TITLE = "ic_integrity_emulator_title";
    private static final String INTEGRITY_EMULATOR_TEXT = "ic_integrity_emulator_text";
    private static final String INTEGRITY_BROKEN_TITLE = "ic_integrity_broken_title";
    private static final String INTEGRITY_BROKEN_TEXT = "ic_integrity_broken_text";
    private static final String BUTTON_GOTO_STORE = "ic_button_goto_store";
    private static final String BUTTON_CONNECT_SUPPORT = "ic_button_connect_support";
    private static final String CLOSE = "ic_close";

    protected static long sCheckedTime;
    protected static volatile long sCheckStartedTime;

    protected final boolean mDoDebug;
    protected final boolean mIsEmulatorAllowed;
    protected final boolean mIsDebugModeAllowed;

    public ApkValidator(boolean doDebug, boolean isEmulatorAllowed, boolean isDebugModeAllowed) {
        mDoDebug = doDebug;
        mIsEmulatorAllowed = isEmulatorAllowed;
        mIsDebugModeAllowed = isDebugModeAllowed;
    }

    protected abstract String getTag();

    protected abstract String getKeyHash(Context context);

    protected abstract String getSupportEmail(Context context);

    protected String getApkPackage(Context context) {
        return context.getPackageName();
    }

    protected String getString(Context context, String resourceName) {
        //library resources are merged into app context
        final Resources r = context.getResources();
        String packageName = context.getPackageName();
        final int resId = r.getIdentifier(resourceName, "string", packageName);
        if (resId > 0) {
            return r.getString(resId);
        } else {
            return resourceName;
        }
    }

    protected void startExternalActivity(final Activity activity, final String mask) {
        final Intent marketIntent = new Intent(Intent.ACTION_VIEW, Uri.parse(String.format(mask, activity.getPackageName())));
        activity.startActivity(marketIntent);
    }

    protected void sendEmailSimple(final Activity activity, final String toEmail, final String subject,
                                   final String body) {
        final Intent intent = new Intent(Intent.ACTION_SENDTO);
        intent.setType("message/rfc822");
        try {
            String uriText = String.format("mailto:%s?subject=%s&body=%s", toEmail, URLEncoder.encode(subject, "utf-8"),
                    URLEncoder.encode(body, "utf-8"));
            intent.setData(Uri.parse(uriText));
            activity.startActivity(intent);
        } catch (final android.content.ActivityNotFoundException ex) {
            Toast.makeText(activity, getString(activity, NO_EMAIL_CLIENT_FOUND), Toast.LENGTH_SHORT).show();
        } catch (UnsupportedEncodingException e) {
            Toast.makeText(activity, "Unsupported encoding", Toast.LENGTH_SHORT).show();
        } finally {
            exit();
        }
    }

    protected void checkIntegrity(Context context) {
        if (context == null) {
            return;
        }
        final Context appContext = context.getApplicationContext();
        if (appContext == null) {
            return;
        }
        long now = System.currentTimeMillis();
        //limit execution calls to once in an hour
        if (sCheckedTime + DateUtils.HOUR_IN_MILLIS < now && sCheckStartedTime + DateUtils.MINUTE_IN_MILLIS < now) {
            sCheckStartedTime = now;
            info(appContext, "connecting");
            final long randomDelay = new Random().nextInt(5000);
            SoftReference<Context> ref = new SoftReference<>(appContext);
            new Handler(Looper.getMainLooper()).postDelayed(() -> delayedValidation(ref), randomDelay);
        } else {
            log(appContext, "-");
        }
    }

    protected void delayedValidation(SoftReference<Context> ref) {
        final Context context = ref.get();
        if (context != null) {
            AsyncTask.THREAD_POOL_EXECUTOR.execute(() -> safeAsyncValidation(ref));
        }
    }

    protected void safeAsyncValidation(SoftReference<Context> ref) {
        final Context context = ref.get();
        if (context != null) {
            log(context, "validating....");
            try {
                validation(context);
            } catch (final Throwable e) {
                log(context, e.getMessage());
                exit(context);
            }
        }
    }

    protected void validation(Context context) {
        log(context, "call validate");
        context = context.getApplicationContext();
        if (context == null) {
            return;
        }

        if (!mIsEmulatorAllowed) {
            log(context, "call emulator check");
            if (isEmulator(context)) {
                //emulator
                log(context, "emulator, exiting");
                exit(context, true);
                return;
            }
        }

        if (!mIsDebugModeAllowed) {
            log(context, "call debug check");
            if (isDebuggable(context)) {
                log(context, "debug, exiting");
                exit(context, true);
                return;
            }
        }
        //check application classes
        Application application = getApplication(context);
        if (application != null) {
            Class<? extends Application> appClass = application.getClass();
            if (!getAppClassName().equals(appClass.getName())) {
                info(context, "a1");
                exit(context, false);
                return;
            }
            Class<?> superclass = appClass.getSuperclass();
            if (superclass == null || !getAppParentClassName().equals(superclass.getName())) {
                info(context, "a2");
                exit(context, false);
                return;
            }
        }
        //check hooks library
        //System.loadLibrary();
        log(context, "call libs check");
        if (hasBadLib(context)) {
            log(context, "failed");
            exit(context);
            return;
        }

        log(context, "call signature check");
        if (!isSignatureOk(context)) {
            log(context, "failed");
            exit(context);
            return;
        }
        info(context, "connection is ok");
        log(context, "signature is fine, no termination");
        //update time only if validation was ok
        sCheckedTime = System.currentTimeMillis();
    }

    protected void exit(Context context) {
        exit(context, false);
    }

    protected void exit(Context context, boolean isEmulator) {
        info(context, "-");
        Activity a = getTopActivity(context);
        if (a != null) {
            if (isEmulator) {
                showAppTerminateDialog(a,//
                        getString(a, INTEGRITY_EMULATOR_TITLE), //
                        getString(a, INTEGRITY_EMULATOR_TEXT), //
                        null);
            } else {
                showAppTerminateDialog(a,//
                        getString(a, INTEGRITY_BROKEN_TITLE), //
                        getString(a, INTEGRITY_BROKEN_TEXT), //
                        getString(a, BUTTON_GOTO_STORE));
            }
        } else {
            //exit with delay
            exit();
        }
    }

    protected boolean hasBadLib(Context context) {
        try {
            String mapsFile = "/proc/" + android.os.Process.myPid() + "/maps";
            BufferedReader reader = new BufferedReader(new FileReader(mapsFile));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.endsWith(".so")) {
                    int n = line.lastIndexOf(" ");
                    String lib = line.substring(n + 1);
                    log(context, lib);
                    String lowLib = lib.toLowerCase(Locale.US);
                    if (lowLib.contains("aturekil")) {
                        info(context, "k1");
                        return true;
                    }
                    if (lowLib.contains("signkill")) {
                        info(context, "k2");
                        return true;
                    }
                    if (lowLib.contains("apkkill")) {
                        info(context, "k3");
                        return true;
                    }
                }
            }
        } catch (Throwable e) {
            log(context, e.getMessage());
        }
        return false;
    }

    protected void exit() {
        new Handler(Looper.getMainLooper()).postDelayed(this::immediateExit, 500);
    }

    private void immediateExit() {
        System.exit(1);
    }

    protected boolean isSignatureOk(final Context context) {
        try {
            //1 step find our certificate in package manager
            X509Certificate pmCert = findCertificateByPackageManager(context);
            if (pmCert == null) {
                info(context, "pm");
                return false; // no cert with our thumbprint, something is wrong
            }
            String pmCertThumb = getThumbPrint(pmCert);
            log(context, "pm cert:" + pmCertThumb);
            String apkPath = normalizeApkPath(context, context.getPackageCodePath());
            if (apkPath == null) {
                info(context, "p1");
                return false;
            }
            log(context, "p1 is fine");
            String apkPath2 = normalizeApkPath(context, context.getPackageManager().getApplicationInfo(getApkPackage(context), 0).publicSourceDir);
            if (apkPath2 == null) {
                info(context, "p2");
                return false;
            }
            log(context, "p2 is fine");
            if (!apkPath.equals(apkPath2)) {
                info(context, "p3");
                return false;
            }
            log(context, "paths are equal");
            final int versionCode = getVersionCode(context);
            final int apkVersionCodeByPackageManager = getApkVersionCodeByPackageManager(context, apkPath);
            log(context, "v1 avc=" + apkVersionCodeByPackageManager);
            if (versionCode != apkVersionCodeByPackageManager) {
                info(context, "v1" + apkVersionCodeByPackageManager);
                return false;
            }
            log(context, "v1 is fine");
            final int apkVersionCode = getApkVersionCode(context, apkPath);
            log(context, "v2 avc=" + apkVersionCode);
            if (versionCode != apkVersionCode) {
                info(context, "v2" + apkVersionCode);
                return false;
            }
            log(context, "v2 is fine");
            if (!checkFileCert(context, pmCertThumb, new File(apkPath))) {
                info(context, "s");
                return false;
            }
            return true;
        } catch (Throwable e) {
            error(context, e);
        }
        return false;
    }

    protected String normalizeApkPath(Context context, String path) {
        File file = new File(path);
        if (!file.exists()) {
            return null;
        }
        try {
            path = file.getCanonicalPath();
        } catch (Throwable e) {
            error(context, e);
        }
        if (path == null) {
            return null;
        }
        @SuppressLint("SdCardPath")
        boolean startCondition = path.startsWith("/data/app/")
                || path.startsWith("/mnt/expand/")
                || path.startsWith("/data/internal_app/")
                || path.startsWith("/data/user/0/com.gbox.android/")
                || path.startsWith("/data/data/com.gbox.android/");
        if (startCondition) {
            if (path.contains(getApkPackage(context))) {
                return path;
            }
        }
        info(context, path);
        return null;
    }

    //1 check apk version
    protected int getApkVersionCodeByPackageManager(Context context, String apkPath) {
        final PackageInfo pInfo = context.getPackageManager().getPackageArchiveInfo(apkPath, 0);
        if (android.os.Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            return (int) pInfo.getLongVersionCode();
        } else {
            //noinspection deprecation
            return pInfo.versionCode;
        }
    }

    protected abstract String getAppClassName();

    protected abstract String getAppParentClassName();

    protected abstract int getVersionCode(Context context);

    protected abstract int getApkVersionCode(Context context, String path);

    protected boolean checkFileCert(Context context, String pmCertThumb, File apkFile) throws NoSuchAlgorithmException, CertificateEncodingException {
        X509Certificate apkCert = findCertificateByFile(context, apkFile);
        if (apkCert == null) {
            return false;
        }
        String apkCertThumb = getThumbPrint(apkCert);
        log(context, "apk cert thumb:" + apkCertThumb);
        //compare certs
        return pmCertThumb.equals(apkCertThumb);
    }

    protected X509Certificate findCertificateByPackageManager(final Context context) {
        log(context, "pm cert search");
        try {
            @SuppressLint("PackageManagerGetSignatures") final Signature[] signatures = context.getPackageManager().getPackageInfo(context.getPackageName(),
                    PackageManager.GET_SIGNATURES).signatures;
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");

            for (final Signature signature : signatures) {

                try {
                    // cert = DER encoded X.509 certificate:
                    final X509Certificate c = (X509Certificate) certificateFactory.generateCertificate(
                            new ByteArrayInputStream(signature.toByteArray()));
                    final String thumbPrint = getThumbPrint(c);
                    log(context, "pm cert processing... " + thumbPrint);
                    if (getKeyHash(context).equals(thumbPrint)) {
                        log(context, "pm cert found");
                        return c;
                    }
                } catch (Throwable e1) {
                    log(context, "pm cert error" + e1.getMessage());
                    error(context, e1);
                }
            }
        } catch (final Throwable ex) {
            log(context, "pm cert factory error" + ex.getMessage());
            error(context, ex);
        }
        log(context, "pm cert is not found");
        error(context, "c");
        return null;
    }

    protected X509Certificate findCertificateByFile(Context context, File file) {
        log(context, "file cert test " + file.getAbsolutePath());
        try {
            com.android.apksig.ApkVerifier.Builder builder = new com.android.apksig.ApkVerifier.Builder(file);
            log(context, "file cert verify");
            com.android.apksig.ApkVerifier.Result result = builder.build().verify();
            List<X509Certificate> signerCertificates = result.getSignerCertificates();
            X509Certificate signerCertificate = (signerCertificates == null || signerCertificates.isEmpty() ? null : signerCertificates.get(0));
            if (!result.isVerified()) {
                String tp = "";
                if (signerCertificate != null) {
                    tp = " " + getThumbPrint(signerCertificates.get(0));
                }
                error(context, "fv failed" + tp);
                if (mDoDebug) {
                    List<com.android.apksig.ApkVerifier.IssueWithParams> errors = result.getErrors();
                    log(context, "file cert verification failed, errors:" + errors.size());
                    for (com.android.apksig.ApkVerifier.IssueWithParams issue : errors) {
                        error(context, String.valueOf(issue));
                    }
                    List<com.android.apksig.ApkVerifier.IssueWithParams> warnings = result.getWarnings();
                    log(context, "file cert verification failed, warnings:" + warnings.size());
                    for (com.android.apksig.ApkVerifier.IssueWithParams warn : warnings) {
                        log(context, "file cert warn:" + warn);
                    }
                }
                return null;
            }
            log(context, "file cert verification successful");
            return signerCertificate;
        } catch (Throwable e) {
            error(context, e);
        }
        return null;
    }

    //TODO: look at the https://github.com/framgia/android-emulator-detector
    protected boolean isEmulator(Context context) {
        try {
            String gfp = System.getProperty("ro.hardware", "");
            boolean goldfish = gfp != null && gfp.contains("goldfish");
            String qemu = System.getProperty("ro.kernel.qemu", "");
            boolean emu = qemu != null && !qemu.isEmpty();
            String sdkProperty = System.getProperty("ro.product.model", "");
            boolean sdk = "sdk".equals(sdkProperty);
            if (emu || goldfish || sdk) {
                return true;
            }

            String fingerprint = Build.FINGERPRINT.toLowerCase();
            String model = Build.MODEL.toLowerCase();
            String manufacturer = Build.MANUFACTURER.toLowerCase();
            String brand = Build.BRAND.toLowerCase();
            String device = Build.DEVICE.toLowerCase();
            String product = Build.PRODUCT.toLowerCase();
            return fingerprint.contains("generic")
                    || fingerprint.startsWith("unknown")
                    || model.contains("google_sdk")
                    || model.contains("emulator")
                    || model.contains("android sdk built for x86")
                    || manufacturer.contains("genymotion")
                    || (brand.startsWith("generic") && device.startsWith("generic"))
                    || "google_sdk".equals(product)
                    || Build.HARDWARE.contains("goldfish");
        } catch (Throwable e) {
            error(context, e);
            return false;
        }
    }

    protected boolean isDebuggable(Context context) {
        try {
            return (context.getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
        } catch (Throwable e) {
            error(context, e);
            return true;
        }
    }

    protected void showAppTerminateDialog(final Activity activity, final String title, final String text,
                                          final String marketTitle) {
        log(activity, "creating dialog...");
        if (activity == null || activity.isFinishing()) {
            return;
        }
        log(activity, "title:" + title + ", text: " + text);
        //otherwise bug - empty title and message
        final AlertDialog.Builder builder;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            builder = new AlertDialog.Builder(activity, android.R.style.Theme_Material_Light_Dialog_Alert);
        } else {
            builder = new AlertDialog.Builder(activity);
        }

        builder.setTitle(title)
                .setMessage(text)
                .setCancelable(true);
        if (marketTitle != null) {
            builder.setNeutralButton(getString(activity, BUTTON_CONNECT_SUPPORT),
                            (dialog, which) -> {
                                String versionName;
                                try {
                                    final PackageInfo info = activity.getPackageManager().getPackageInfo(
                                            activity.getPackageName(), 0);
                                    versionName = info.versionName;
                                } catch (final NameNotFoundException ex) {
                                    versionName = "Unknown";
                                }

                                final String body = String.format("Model:%s,\nDevice:%s,\nSDK: %s\nApp: %s\n",
                                        Build.MODEL, Build.DEVICE,
                                        Build.VERSION.RELEASE, versionName);

                                sendEmailSimple(activity, getSupportEmail(activity), title, body);
                                dialog.dismiss();
                                activity.finish();
                            }).setPositiveButton(marketTitle, (dialog, which) -> startMarketActivity(activity))
                    .setOnCancelListener(dialog -> startMarketActivity(activity))
                    .setOnKeyListener((dialog, i, keyEvent) -> {
                        startMarketActivity(activity);
                        return false;
                    });
        } else {
            builder.setNegativeButton(getString(activity, CLOSE), (dialog, which) -> immediateExit())
                    .setOnCancelListener(dialog -> immediateExit())
                    .setOnKeyListener((dialog, i, keyEvent) -> {
                        immediateExit();
                        return false;
                    });


        }
        // starting in UI thread
        activity.runOnUiThread(builder::show);
    }

    protected String getInternalMarketUrl() {
        return "market://details?id=%s";
    }

    protected String getExternalMarketUrl() {
        return "https://play.google.com/store/apps/details?id=%s";
    }

    protected void startMarketActivity(final Activity activity) {
        try {
            startExternalActivity(activity, getInternalMarketUrl());
        } catch (final Throwable e) {
            startExternalActivity(activity, getExternalMarketUrl());
        } finally {
            exit();
        }
    }

    protected Application getApplication(Context context) {
        if (context == null) {
            return null;
        }
        if (context instanceof ContextWrapper) {
            if (Application.class.isAssignableFrom(context.getClass())) {
                return (Application) context;
            } else {
                return getApplication(((ContextWrapper) context).getBaseContext());
            }
        }
        return null;
    }

    protected Activity getTopActivity(Context context) {
        Application application = getApplication(context.getApplicationContext());
        if (application == null) {
            return null;
        }
        //get topActivity property by reflection
        try {
            Field f = application.getClass().getDeclaredField("topActivity");
            f.setAccessible(true);
            if (f.isAccessible()) {
                return (Activity) f.get(application);
            }
        } catch (Throwable e) {
            //nothing
            log(context, e.getMessage());
        }
        return null;
    }

    protected void info(Context context, String msg) {
        Log.i(getTag(), msg);
    }

    protected void log(Context context, String msg) {
        Log.d(getTag(), msg);
    }

    protected void error(Context context, Throwable e) {
        Log.e(getTag(), e.getMessage());
    }

    protected void error(Context context, String msg) {
        Log.e(getTag(), msg);
    }

    protected static String getThumbPrint(final X509Certificate cert) throws NoSuchAlgorithmException,
            CertificateEncodingException {
        final MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(cert.getEncoded());
        return hexify(md.digest());
    }

    protected static String hexify(final byte[] bytes) {
        final char[] hexDigits = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
        final StringBuilder buf = new StringBuilder(bytes.length * 2);

        for (byte aByte : bytes) {
            buf.append(hexDigits[(aByte & 0xf0) >> 4]);
            buf.append(hexDigits[aByte & 0x0f]);
        }
        return buf.toString();
    }

    /**
     * Make it public to be cached by the classloader while loading main class
     */
    public static Class<?>[] classes = new Class<?>[]{
            com.android.apksig.apk.ApkFormatException.class,//
            com.android.apksig.apk.ApkSigningBlockNotFoundException.class,//
            com.android.apksig.apk.ApkUtils.class,//
            com.android.apksig.apk.ApkUtils.ApkSigningBlock.class,//
            com.android.apksig.apk.ApkUtils.ZipSections.class,//
            //
            com.android.apksig.apk.CodenameMinSdkVersionException.class,//
            com.android.apksig.apk.MinSdkVersionException.class,//
            com.android.apksig.ApkSigner.class,//
            com.android.apksig.ApkSigner.Builder.class,//
            com.android.apksig.ApkSigner.SignerConfig.class,//
            //
            com.android.apksig.ApkSignerEngine.class,//
            com.android.apksig.ApkSignerEngine.InputJarEntryInstructions.class,//
            com.android.apksig.ApkSignerEngine.InspectJarEntryRequest.class,//
            com.android.apksig.ApkSignerEngine.OutputApkSigningBlockRequest.class,//
            com.android.apksig.ApkSignerEngine.OutputApkSigningBlockRequest2.class,//
            com.android.apksig.ApkSignerEngine.OutputJarSignatureRequest.class,//
            //
            com.android.apksig.ApkVerifier.class,//
            com.android.apksig.ApkVerifier.Result.class,//
            com.android.apksig.ApkVerifier.Builder.class,//
            com.android.apksig.ApkVerifier.Issue.class,//
            com.android.apksig.ApkVerifier.IssueWithParams.class,//
            //
            com.android.apksig.DefaultApkSignerEngine.OutputJarSignatureRequest.class,//
            com.android.apksig.DefaultApkSignerEngine.OutputApkSigningBlockRequest.class,//
            com.android.apksig.DefaultApkSignerEngine.OutputApkSigningBlockRequest2.class,//
            com.android.apksig.DefaultApkSignerEngine.OutputJarSignatureRequest.class,//
            com.android.apksig.DefaultApkSignerEngine.InspectJarEntryRequest.class,//
            com.android.apksig.DefaultApkSignerEngine.Builder.class,//
            com.android.apksig.DefaultApkSignerEngine.SignerConfig.class,//
            //
            com.android.apksig.Hints.class,//
            com.android.apksig.Hints.ByteRange.class,//
            //
            com.android.apksig.internal.apk.AndroidBinXmlParser.class,//
            com.android.apksig.internal.apk.AndroidBinXmlParser.XmlParserException.class,//
            //
            com.android.apksig.internal.apk.ApkSigningBlockUtils.class,//
            com.android.apksig.internal.apk.ApkSigningBlockUtils.NoSupportedSignaturesException.class,//
            com.android.apksig.internal.apk.ApkSigningBlockUtils.SignerConfig.class,//
            com.android.apksig.internal.apk.ApkSigningBlockUtils.Result.class,//
            com.android.apksig.internal.apk.ApkSigningBlockUtils.SignatureNotFoundException.class,//
            //
            com.android.apksig.internal.apk.ContentDigestAlgorithm.class,//
            com.android.apksig.internal.apk.SignatureAlgorithm.class,//
            com.android.apksig.internal.apk.SignatureInfo.class,//
            com.android.apksig.internal.apk.v1.DigestAlgorithm.class,//
            com.android.apksig.internal.apk.v1.V1SchemeSigner.class,//
            com.android.apksig.internal.apk.v1.V1SchemeSigner.OutputManifestFile.class,//
            com.android.apksig.internal.apk.v1.V1SchemeSigner.SignerConfig.class,//
            //
            com.android.apksig.internal.apk.v1.V1SchemeVerifier.class,//
            com.android.apksig.internal.apk.v1.V1SchemeVerifier.ObjectIdentifierChoice.class,//
            com.android.apksig.internal.apk.v1.V1SchemeVerifier.OctetStringChoice.class,//
            com.android.apksig.internal.apk.v1.V1SchemeVerifier.Result.class,//
            //
            com.android.apksig.internal.apk.v2.V2SchemeSigner.class,//
            com.android.apksig.internal.apk.v2.V2SchemeVerifier.class,//
            com.android.apksig.internal.apk.v3.V3SchemeSigner.class,//
            com.android.apksig.internal.apk.v3.V3SchemeVerifier.class,//
            com.android.apksig.internal.apk.v3.V3SigningCertificateLineage.class,//
            com.android.apksig.internal.apk.v3.V3SigningCertificateLineage.SigningCertificateNode.class,//
            //
            com.android.apksig.internal.asn1.Asn1BerParser.class,//
            com.android.apksig.internal.asn1.Asn1Class.class,//
            com.android.apksig.internal.asn1.Asn1DecodingException.class,//
            com.android.apksig.internal.asn1.Asn1DerEncoder.class,//
            com.android.apksig.internal.asn1.Asn1EncodingException.class,//
            com.android.apksig.internal.asn1.Asn1Field.class,//
            com.android.apksig.internal.asn1.Asn1OpaqueObject.class,//
            com.android.apksig.internal.asn1.Asn1TagClass.class,//
            com.android.apksig.internal.asn1.Asn1Tagging.class,//
            com.android.apksig.internal.asn1.Asn1Type.class,//
            com.android.apksig.internal.asn1.ber.BerDataValue.class,//
            com.android.apksig.internal.asn1.ber.BerDataValueFormatException.class,//
            com.android.apksig.internal.asn1.ber.BerDataValueReader.class,//
            com.android.apksig.internal.asn1.ber.BerEncoding.class,//
            com.android.apksig.internal.asn1.ber.ByteBufferBerDataValueReader.class,//
            com.android.apksig.internal.asn1.ber.InputStreamBerDataValueReader.class,//
            com.android.apksig.internal.jar.ManifestParser.class,//
            com.android.apksig.internal.jar.ManifestParser.Attribute.class,//
            com.android.apksig.internal.jar.ManifestParser.Section.class,//
            //
            com.android.apksig.internal.jar.ManifestWriter.class,//
            com.android.apksig.internal.jar.SignatureFileWriter.class,//
            com.android.apksig.internal.pkcs7.AlgorithmIdentifier.class,//
            com.android.apksig.internal.pkcs7.Attribute.class,//
            com.android.apksig.internal.pkcs7.ContentInfo.class,//
            com.android.apksig.internal.pkcs7.EncapsulatedContentInfo.class,//
            com.android.apksig.internal.pkcs7.IssuerAndSerialNumber.class,//
            com.android.apksig.internal.pkcs7.Pkcs7Constants.class,//
            com.android.apksig.internal.pkcs7.Pkcs7DecodingException.class,//
            com.android.apksig.internal.pkcs7.SignedData.class,//
            com.android.apksig.internal.pkcs7.SignerIdentifier.class,//
            com.android.apksig.internal.pkcs7.SignerInfo.class,//
            com.android.apksig.internal.util.AndroidSdkVersion.class,//
            com.android.apksig.internal.util.ByteArrayDataSink.class,//
            com.android.apksig.internal.util.ByteBufferDataSource.class,//
            com.android.apksig.internal.util.ByteBufferSink.class,//
            com.android.apksig.internal.util.ByteBufferUtils.class,//
            com.android.apksig.internal.util.ByteStreams.class,//
            com.android.apksig.internal.util.ChainedDataSource.class,//
            com.android.apksig.internal.util.DelegatingX509Certificate.class,//
            com.android.apksig.internal.util.GuaranteedEncodedFormX509Certificate.class,//
            com.android.apksig.internal.util.InclusiveIntRange.class,//
            com.android.apksig.internal.util.MessageDigestSink.class,//
            com.android.apksig.internal.util.OutputStreamDataSink.class,//
            com.android.apksig.internal.util.Pair.class,//
            com.android.apksig.internal.util.RandomAccessFileDataSink.class,//
            com.android.apksig.internal.util.RandomAccessFileDataSource.class,//
            com.android.apksig.internal.util.TeeDataSink.class,//
            com.android.apksig.internal.util.VerityTreeBuilder.class,//
            com.android.apksig.internal.util.X509CertificateUtils.class,//
            com.android.apksig.internal.x509.AttributeTypeAndValue.class,//
            com.android.apksig.internal.x509.Certificate.class,//
            com.android.apksig.internal.x509.Extension.class,//
            com.android.apksig.internal.x509.Name.class,//
            com.android.apksig.internal.x509.RelativeDistinguishedName.class,//
            com.android.apksig.internal.x509.SubjectPublicKeyInfo.class,//
            com.android.apksig.internal.x509.TBSCertificate.class,//
            com.android.apksig.internal.x509.Time.class,//
            com.android.apksig.internal.x509.Validity.class,//
            com.android.apksig.internal.zip.CentralDirectoryRecord.class,//
            com.android.apksig.internal.zip.EocdRecord.class,//
            com.android.apksig.internal.zip.LocalFileRecord.class,//
            com.android.apksig.internal.zip.ZipUtils.class,//
            com.android.apksig.internal.zip.ZipUtils.DeflateResult.class,//
            //
            com.android.apksig.SigningCertificateLineage.class,//
            com.android.apksig.SigningCertificateLineage.Builder.class,//
            com.android.apksig.SigningCertificateLineage.SignerCapabilities.class,//
            com.android.apksig.SigningCertificateLineage.SignerConfig.class,//
            //
            com.android.apksig.util.DataSink.class,//
            com.android.apksig.util.DataSinks.class,//
            com.android.apksig.util.DataSource.class,//
            com.android.apksig.util.DataSources.class,//
            com.android.apksig.util.ReadableDataSink.class,//
            com.android.apksig.zip.ZipFormatException.class//
    };
}
