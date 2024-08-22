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
import android.content.DialogInterface;
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
import android.view.KeyEvent;
import android.widget.Toast;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.lang.ref.WeakReference;
import java.lang.reflect.Field;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Random;
import java.util.jar.JarFile;
import java.util.zip.ZipEntry;

@SuppressWarnings("deprecation")
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
        long now = System.currentTimeMillis();
        //limit execution calls to once in an hour
        //TODO: sync and lock
        if (sCheckedTime + DateUtils.HOUR_IN_MILLIS < now) {
            Log.i(getTag(), "+");
            IntegrityChecker integrityChecker = new IntegrityChecker(context, ApkValidator.this);
            integrityChecker.execute();
        } else {
            log(context, "-");
        }
    }

    protected void validate(final Context context) {
        log(context, "call b");

        if (!mIsEmulatorAllowed) {
            log(context, "call emulator check");
            if (isEmulator()) {
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

        log(context, "call signature check");
        if (!isSignatureOk(context)) {
            log(context, "failed");
            exit(context);
            return;
        }
        Log.i(getTag(), getTag());

        log(context, "signature is fine, no termination");
        //update time only if validation was ok
        sCheckedTime = System.currentTimeMillis();
    }

    protected void exit(Context context) {
        exit(context, false);
    }

    protected void exit(Context context, boolean isEmulator) {
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

    protected void exit() {
        new Handler(Looper.getMainLooper()).postDelayed(new Runnable() {
            @Override
            public void run() {
                immediateExit();
            }
        }, 500);
    }

    private void immediateExit() {
        System.exit(1);
    }

    protected boolean isSignatureOk(final Context context) {
        //do not check signature in debug mode, android studio fails to generate MANIFEST.MF now
        if (mIsDebugModeAllowed && mIsEmulatorAllowed) {
            log(context, "No signature check because no META-INF/MANIFEST.MF generated");
            return true;
        }
        try {
            X509Certificate pmCert = findCertificateByPackageManager(context);
            if (pmCert == null) {
                return false;
            }
            String pmCertThumb = getThumbPrint(pmCert);
            log(context, "pmCertThumb:" + pmCertThumb);
            //verification  is here
            File apkFile = new File(context.getApplicationContext().getPackageCodePath());
            if (!checkFileCert(pmCertThumb, apkFile)) return false;
            ApplicationInfo ai = context.getPackageManager().getApplicationInfo(getApkPackage(context), 0);
            File apkFile2 = new File(ai.publicSourceDir);
            if (!apkFile2.equals(apkFile)) {
                log(context, "apkFile and apkFile2 are different!");
                return checkFileCert(pmCertThumb, apkFile2);
            }
            return true;
        } catch (Throwable e) {
            error(context, e);
        }
        return false;
    }

    //1 check apk version
    protected boolean checkFileVersionByPackageInfo(Context context, File apkFile) {
        PackageInfo info = context.getPackageManager().getPackageArchiveInfo(apkFile.getAbsolutePath(), 0);
        return info.versionCode != getVersionCode();
    }

    private int getApkVersionCode(String path) {
        try {
            if ((new File(path).exists())) {
                JarFile jf = new JarFile(path);
                final ZipEntry entry = jf.getEntry("META-INF/androidx.code.version");
                if (entry != null) {
                    InputStream is = jf.getInputStream(entry);
                    //read to byte array
                    byte[] bytes = new byte[is.available()];
                    DataInputStream dis = new DataInputStream(is);
                    dis.readFully(bytes);
                    dis.close();
                    String versionString = new String(bytes, StandardCharsets.UTF_8);
                    return Integer.parseUnsignedInt(versionString);
                }
            }
        } catch (Exception ex) {
            error(context, "cv is not found");
        }
        return -1;
    }

    protected abstract int getVersionCode();

    protected boolean checkFileCert(String pmCertThumb, File apkFile) throws NoSuchAlgorithmException, CertificateEncodingException {
        X509Certificate apkCert = findCertificateByFile(apkFile);
        if (apkCert == null) {
            return false;
        }
        String apkCertThumb = getThumbPrint(apkCert);
        log(context, "apkCertThumb:" + apkCertThumb);
        //compare certs
        return pmCertThumb.equals(apkCertThumb);
    }

    protected X509Certificate findCertificateByPackageManager(final Context context) {
        log(context, "finding certificate...");
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
                    log(context, "Cer/sig processing... " + thumbPrint);
                    if (getKeyHash(context).equals(thumbPrint)) {
                        log(context, "Cer/sig found");
                        return c;
                    }
                } catch (Throwable e1) {
                    log(context, "cer error" + e1.getMessage());
                    error(context, e1);
                }
            }
        } catch (final Throwable ex) {
            log(context, "cer factory error" + ex.getMessage());
            error(context, ex);
        }
        log(context, "Sig is not ok, cert is not found");
        error(context, "c is not found");
        return null;
    }

    protected X509Certificate findCertificateByFile(final File file) {
        log(context, "findCertificateByFile file=" + file.getAbsolutePath());
        try {
            com.android.apksig.ApkVerifier.Builder builder = new com.android.apksig.ApkVerifier.Builder(file);
            log(context, "findCertificateByFile verify...");
            com.android.apksig.ApkVerifier.Result result = builder.build().verify();
            if (!result.isVerified()) {
                error(context, "Verification failed");
                if (mDoDebug) {
                    List<com.android.apksig.ApkVerifier.IssueWithParams> errors = result.getErrors();
                    log(context, "Verification failed, errors:" + errors.size());
                    for (com.android.apksig.ApkVerifier.IssueWithParams issue : errors) {
                        log(context, "findCertificateByFile error:" + issue.toString());
                    }
                    List<com.android.apksig.ApkVerifier.IssueWithParams> warnings = result.getWarnings();
                    log(context, "Verification failed, warnings:" + warnings.size());
                    for (com.android.apksig.ApkVerifier.IssueWithParams warn : warnings) {
                        log(context, "findCertificateByFile warn:" + warn.toString());
                    }
                }
                return null;
            }
            log(context, "findCertificateByFile verification successful");

            List<X509Certificate> signerCertificates = result.getSignerCertificates();
            return signerCertificates.get(0);
        } catch (Throwable e) {
            error(e, context);
        }
        return null;
    }

    //TODO: look at the https://github.com/framgia/android-emulator-detector
    protected boolean isEmulator() {
        try {
            String gfp = System.getProperty("ro.hardware", "");
            boolean goldfish = gfp.contains("goldfish");
            String qemu = System.getProperty("ro.kernel.qemu", "");
            boolean emu = qemu.length() > 0;
            String sdkProperty = System.getProperty("ro.product.model", "");
            boolean sdk = sdkProperty.equals("sdk");

            String fingerprint = Build.FINGERPRINT.toLowerCase();
            String model = Build.MODEL.toLowerCase();
            String manufacturer = Build.MANUFACTURER.toLowerCase();
            String brand = Build.BRAND.toLowerCase();
            String device = Build.DEVICE.toLowerCase();
            String product = Build.PRODUCT.toLowerCase();
            boolean extraCheck = fingerprint.contains("generic")
                    || fingerprint.startsWith("unknown")
                    || model.contains("google_sdk")
                    || model.contains("emulator")
                    || model.contains("android sdk built for x86")
                    || manufacturer.contains("genymotion")
                    || (brand.startsWith("generic") && device.startsWith("generic"))
                    || "google_sdk".equals(product)
                    || Build.HARDWARE.contains("goldfish");

            return (emu || goldfish || sdk || extraCheck);
        } catch (Throwable e) {
            error(e, context);
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
        log(activity, "Title:" + title + ", text: " + text);
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
                    new DialogInterface.OnClickListener() {

                        @Override
                        public void onClick(final DialogInterface dialog, final int which) {

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
                        }
                    }).setPositiveButton(marketTitle, new DialogInterface.OnClickListener() {
                @Override
                public void onClick(final DialogInterface dialog, final int which) {
                    startMarketActivity(activity);
                }
            }).setOnCancelListener(new DialogInterface.OnCancelListener() {
                @Override
                public void onCancel(DialogInterface dialog) {
                    startMarketActivity(activity);
                }
            }).setOnKeyListener(new DialogInterface.OnKeyListener() {
                @Override
                public boolean onKey(final DialogInterface dialog, final int i, final KeyEvent keyEvent) {
                    startMarketActivity(activity);
                    return false;
                }
            });
        } else {
            builder.setNegativeButton(getString(activity, CLOSE), new DialogInterface.OnClickListener() {
                @Override
                public void onClick(DialogInterface dialog, int which) {
                    immediateExit();

                }
            }).setOnCancelListener(new DialogInterface.OnCancelListener() {
                @Override
                public void onCancel(DialogInterface dialog) {
                    immediateExit();
                }
            }).setOnKeyListener(new DialogInterface.OnKeyListener() {
                @Override
                public boolean onKey(final DialogInterface dialog, final int i, final KeyEvent keyEvent) {
                    immediateExit();
                    return false;
                }
            });


        }
        // starting in UI thread
        activity.runOnUiThread(new Runnable() {

            @Override
            public void run() {
                builder.show();
            }
        });

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

    protected void onBeforeValidation() {
        //random pause
        try {
            final long someTime = new Random().nextInt(10000);
            Thread.sleep(someTime);
        } catch (final InterruptedException e) {
            // nothing
        }
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

        for (int i = 0; i < bytes.length; ++i) {
            buf.append(hexDigits[(bytes[i] & 0xf0) >> 4]);
            buf.append(hexDigits[bytes[i] & 0x0f]);
        }
        return buf.toString();
    }

    private static final class IntegrityChecker extends AsyncTask<Void, Void, Boolean> {

        private final WeakReference<Context> _contextRef;

        private final ApkValidator _validator;

        IntegrityChecker(final Context context, ApkValidator validator) {
            _contextRef = new WeakReference<>(context);
            _validator = validator;
        }

        @Override
        protected Boolean doInBackground(final Void... params) {
            _validator.log(context, "doInBackground....");
            _validator.onBeforeValidation();
            _validator.log(context, "validating....");
            try {
                final Context context = _contextRef.get();
                if (context != null) {
                    _validator.validate(context);
                    return true;
                }
                return false;
            } catch (final Throwable e) {
                _validator.log(context, e.getMessage());
            }
            return false;
        }

        @Override
        protected void onPostExecute(Boolean result) {
            if (!result) {
                final Context context = _contextRef.get();
                if (context != null) {
                    _validator.exit(context);
                } else {
                    _validator.exit();
                }
            }
        }
    }

    /**
     * Make it public to be cached by the classloader while loading main class
     */
    public static Class<?>[] classes = new Class<?>[]{
            IntegrityChecker.class,//

            com.android.apksig.DefaultApkSignerEngine.class, //
            com.android.apksig.apk.ApkFormatException.class, //
            com.android.apksig.apk.CodenameMinSdkVersionException.class, //
            com.android.apksig.apk.ApkSigningBlockNotFoundException.class, //
            com.android.apksig.apk.ApkUtils.class, //
            com.android.apksig.apk.ApkUtilsLite.class, //
            com.android.apksig.apk.MinSdkVersionException.class, //
            com.android.apksig.util.DataSink.class, //
            com.android.apksig.util.ReadableDataSink.class, //
            com.android.apksig.util.DataSources.class, //
            com.android.apksig.util.RunnablesProvider.class, //
            com.android.apksig.util.RunnablesExecutor.class, //
            com.android.apksig.util.DataSinks.class, //
            com.android.apksig.util.DataSource.class, //
            com.android.apksig.Hints.class, //
            com.android.apksig.ApkSignerEngine.class, //
            com.android.apksig.internal.asn1.Asn1EncodingException.class, //
            com.android.apksig.internal.asn1.Asn1DecodingException.class, //
            com.android.apksig.internal.asn1.Asn1TagClass.class, //
            com.android.apksig.internal.asn1.Asn1OpaqueObject.class, //
            com.android.apksig.internal.asn1.Asn1DerEncoder.class, //
            com.android.apksig.internal.asn1.Asn1Tagging.class, //
            com.android.apksig.internal.asn1.Asn1Field.class, //
            com.android.apksig.internal.asn1.Asn1Type.class, //
            com.android.apksig.internal.asn1.Asn1BerParser.class, //
            com.android.apksig.internal.asn1.ber.ByteBufferBerDataValueReader.class, //
            com.android.apksig.internal.asn1.ber.BerDataValueFormatException.class, //
            com.android.apksig.internal.asn1.ber.BerEncoding.class, //
            com.android.apksig.internal.asn1.ber.InputStreamBerDataValueReader.class, //
            com.android.apksig.internal.asn1.ber.BerDataValue.class, //
            com.android.apksig.internal.asn1.ber.BerDataValueReader.class, //
            com.android.apksig.internal.asn1.Asn1Class.class, //
            com.android.apksig.internal.apk.v1.V1SchemeSigner.class, //
            com.android.apksig.internal.apk.v1.V1SchemeConstants.class, //
            com.android.apksig.internal.apk.v1.DigestAlgorithm.class, //
            com.android.apksig.internal.apk.v1.V1SchemeVerifier.class, //
            com.android.apksig.internal.apk.SignatureNotFoundException.class, //
            com.android.apksig.internal.apk.ApkSigningBlockUtilsLite.class, //
            com.android.apksig.internal.apk.SignatureAlgorithm.class, //
            com.android.apksig.internal.apk.ApkSigningBlockUtils.class, //
            com.android.apksig.internal.apk.ApkSupportedSignature.class, //
            com.android.apksig.internal.apk.ContentDigestAlgorithm.class, //
            com.android.apksig.internal.apk.AndroidBinXmlParser.class, //
            com.android.apksig.internal.apk.SignatureInfo.class, //
            com.android.apksig.internal.apk.v2.V2SchemeConstants.class, //
            com.android.apksig.internal.apk.v2.V2SchemeVerifier.class, //
            com.android.apksig.internal.apk.v2.V2SchemeSigner.class, //
            com.android.apksig.internal.apk.v4.V4SchemeSigner.class, //
            com.android.apksig.internal.apk.v4.V4SchemeVerifier.class, //
            com.android.apksig.internal.apk.v4.V4Signature.class, //
            com.android.apksig.internal.apk.v3.V3SchemeVerifier.class, //
            com.android.apksig.internal.apk.v3.V3SchemeConstants.class, //
            com.android.apksig.internal.apk.v3.V3SchemeSigner.class, //
            com.android.apksig.internal.apk.v3.V3SigningCertificateLineage.class, //
            com.android.apksig.internal.apk.NoApkSupportedSignaturesException.class, //
            com.android.apksig.internal.apk.stamp.SourceStampConstants.class, //
            com.android.apksig.internal.apk.stamp.V1SourceStampSigner.class, //
            com.android.apksig.internal.apk.stamp.SourceStampCertificateLineage.class, //
            com.android.apksig.internal.apk.stamp.V2SourceStampVerifier.class, //
            com.android.apksig.internal.apk.stamp.V2SourceStampSigner.class, //
            com.android.apksig.internal.apk.stamp.V1SourceStampVerifier.class, //
            com.android.apksig.internal.apk.ApkSignerInfo.class, //
            com.android.apksig.internal.apk.ApkSigResult.class, //
            com.android.apksig.internal.util.ByteBufferUtils.class, //
            com.android.apksig.internal.util.DelegatingX509Certificate.class, //
            com.android.apksig.internal.util.GuaranteedEncodedFormX509Certificate.class, //
            com.android.apksig.internal.util.X509CertificateUtils.class, //
            com.android.apksig.internal.util.OutputStreamDataSink.class, //
            com.android.apksig.internal.util.Pair.class, //
            com.android.apksig.internal.util.VerityTreeBuilder.class, //
            com.android.apksig.internal.util.ByteBufferSink.class, //
            com.android.apksig.internal.util.ByteBufferDataSource.class, //
            com.android.apksig.internal.util.InclusiveIntRange.class, //
            com.android.apksig.internal.util.ChainedDataSource.class, //
            com.android.apksig.internal.util.ByteStreams.class, //
            com.android.apksig.internal.util.MessageDigestSink.class, //
            com.android.apksig.internal.util.RandomAccessFileDataSink.class, //
            com.android.apksig.internal.util.FileChannelDataSource.class, //
            com.android.apksig.internal.util.AndroidSdkVersion.class, //
            com.android.apksig.internal.util.TeeDataSink.class, //
            com.android.apksig.internal.util.ByteArrayDataSink.class, //
            com.android.apksig.internal.jar.SignatureFileWriter.class, //
            com.android.apksig.internal.jar.ManifestWriter.class, //
            com.android.apksig.internal.jar.ManifestParser.class, //
            com.android.apksig.internal.x509.RelativeDistinguishedName.class, //
            com.android.apksig.internal.x509.Extension.class, //
            com.android.apksig.internal.x509.RSAPublicKey.class, //
            com.android.apksig.internal.x509.Time.class, //
            com.android.apksig.internal.x509.Certificate.class, //
            com.android.apksig.internal.x509.TBSCertificate.class, //
            com.android.apksig.internal.x509.Validity.class, //
            com.android.apksig.internal.x509.Name.class, //
            com.android.apksig.internal.x509.AttributeTypeAndValue.class, //
            com.android.apksig.internal.x509.SubjectPublicKeyInfo.class, //
            com.android.apksig.internal.zip.CentralDirectoryRecord.class, //
            com.android.apksig.internal.zip.EocdRecord.class, //
            com.android.apksig.internal.zip.ZipUtils.class, //
            com.android.apksig.internal.zip.LocalFileRecord.class, //
            com.android.apksig.internal.pkcs7.Pkcs7Constants.class, //
            com.android.apksig.internal.pkcs7.ContentInfo.class, //
            com.android.apksig.internal.pkcs7.SignedData.class, //
            com.android.apksig.internal.pkcs7.IssuerAndSerialNumber.class, //
            com.android.apksig.internal.pkcs7.EncapsulatedContentInfo.class, //
            com.android.apksig.internal.pkcs7.Attribute.class, //
            com.android.apksig.internal.pkcs7.SignerInfo.class, //
            com.android.apksig.internal.pkcs7.AlgorithmIdentifier.class, //
            com.android.apksig.internal.pkcs7.SignerIdentifier.class, //
            com.android.apksig.internal.pkcs7.Pkcs7DecodingException.class, //
            com.android.apksig.internal.oid.OidConstants.class, //
            com.android.apksig.ApkVerificationIssue.class, //
            com.android.apksig.SigningCertificateLineage.class, //
            com.android.apksig.zip.ZipSections.class, //
            com.android.apksig.zip.ZipFormatException.class, //
            com.android.apksig.ApkVerifier.class, //
            com.android.apksig.SourceStampVerifier.class, //
            com.android.apksig.ApkSigner.class, //
            com.android.apksig.Constants.class
    };
}
