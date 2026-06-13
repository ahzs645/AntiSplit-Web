import com.reandroid.apk.APKLogger;
import com.reandroid.apk.ApkBundle;
import com.reandroid.apk.ApkModule;
import com.reandroid.apkeditor.common.AndroidManifestHelper;
import com.reandroid.app.AndroidManifest;
import com.reandroid.archive.ZipEntryMap;
import com.reandroid.arsc.chunk.TableBlock;
import com.reandroid.arsc.chunk.xml.AndroidManifestBlock;
import com.reandroid.arsc.chunk.xml.ResXmlAttribute;
import com.reandroid.arsc.chunk.xml.ResXmlElement;
import com.reandroid.arsc.container.SpecTypePair;
import com.reandroid.arsc.model.ResourceEntry;
import com.reandroid.arsc.value.Entry;
import com.reandroid.arsc.value.ResValue;
import com.reandroid.arsc.value.ValueType;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public class CompareJavaMerge {
    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            throw new IllegalArgumentException("Usage: CompareJavaMerge <input.xapk|apks|zip|apk> <output.apk>");
        }
        File input = new File(args[0]);
        File output = new File(args[1]);
        File workDir = Files.createTempDirectory("antisplit-java-merge-").toFile();
        workDir.deleteOnExit();

        if (input.getName().endsWith(".apk")) {
            Files.copy(input.toPath(), new File(workDir, input.getName()).toPath());
        } else {
            extractApks(input, workDir);
        }

        try (ApkBundle bundle = new ApkBundle(6)) {
            bundle.setAPKLogger(new StdoutLogger());
            bundle.loadApkDirectory(workDir);
            try (ApkModule mergedModule = bundle.mergeModules(true)) {
                sanitizeMergedManifest(mergedModule);
                output.getParentFile().mkdirs();
                mergedModule.writeApk(output);
            }
        }

        System.out.println("javaOutput=" + output.getAbsolutePath());
        System.out.println("javaOutputBytes=" + output.length());
    }

    private static void extractApks(File input, File workDir) throws Exception {
        try (ZipFile zipFile = new ZipFile(input)) {
            for (ZipEntry entry : java.util.Collections.list(zipFile.entries())) {
                if (entry.isDirectory() || !entry.getName().endsWith(".apk")) {
                    continue;
                }
                File output = new File(workDir, new File(entry.getName()).getName());
                try (InputStream in = zipFile.getInputStream(entry);
                     FileOutputStream out = new FileOutputStream(output)) {
                    in.transferTo(out);
                }
            }
        }
    }

    private static void sanitizeMergedManifest(ApkModule mergedModule) {
        if (!mergedModule.hasAndroidManifest()) {
            return;
        }
        AndroidManifestBlock manifest = mergedModule.getAndroidManifest();
        APKLogger logger = new StdoutLogger();

        AndroidManifestHelper.removeAttributeFromManifestById(manifest, AndroidManifest.ID_requiredSplitTypes, logger);
        AndroidManifestHelper.removeAttributeFromManifestById(manifest, AndroidManifest.ID_splitTypes, logger);
        AndroidManifestHelper.removeAttributeFromManifestByName(manifest, AndroidManifest.NAME_splitTypes, logger);
        AndroidManifestHelper.removeAttributeFromManifestByName(manifest, AndroidManifest.NAME_requiredSplitTypes, logger);
        AndroidManifestHelper.removeAttributeFromManifestAndApplication(
                manifest, AndroidManifest.ID_extractNativeLibs, logger, AndroidManifest.NAME_extractNativeLibs);
        AndroidManifestHelper.removeAttributeFromManifestAndApplication(
                manifest, AndroidManifest.ID_isSplitRequired, logger, AndroidManifest.NAME_isSplitRequired);

        ResXmlElement application = manifest.getApplicationElement();
        List<ResXmlElement> splitMetaDataElements = AndroidManifestHelper.listSplitRequired(application);
        boolean splitsRemoved = false;
        for (ResXmlElement meta : splitMetaDataElements) {
            if (!splitsRemoved) {
                boolean result = false;
                ResXmlAttribute nameAttribute = meta.searchAttributeByResourceId(AndroidManifest.ID_name);
                if (nameAttribute != null && "com.android.vending.splits".equals(nameAttribute.getValueAsString())) {
                    ResXmlAttribute valueAttribute = meta.searchAttributeByResourceId(AndroidManifest.ID_value);
                    if (valueAttribute == null) {
                        valueAttribute = meta.searchAttributeByResourceId(AndroidManifest.ID_resource);
                    }
                    if (valueAttribute != null && valueAttribute.getValueType() == ValueType.REFERENCE && mergedModule.hasTableBlock()) {
                        TableBlock tableBlock = mergedModule.getTableBlock();
                        ResourceEntry resourceEntry = tableBlock.getResource(valueAttribute.getData());
                        if (resourceEntry != null) {
                            ZipEntryMap zipEntryMap = mergedModule.getZipEntryMap();
                            for (Entry entry : resourceEntry) {
                                if (entry == null) {
                                    continue;
                                }
                                ResValue resValue = entry.getResValue();
                                if (resValue == null) {
                                    continue;
                                }
                                String path = resValue.getValueAsString();
                                zipEntryMap.remove(path);
                                entry.setNull(true);
                                SpecTypePair specTypePair = entry.getTypeBlock().getParentSpecTypePair();
                                specTypePair.removeNullEntries(entry.getId());
                            }
                            result = true;
                        }
                    }
                }
                splitsRemoved = result;
            }
            application.remove(meta);
        }
        manifest.refresh();
    }

    private static class StdoutLogger implements APKLogger {
        @Override
        public void logMessage(String msg) {
            if (Boolean.getBoolean("antisplit.compare.verbose")) {
                System.out.println(msg);
            }
        }

        @Override
        public void logError(String msg, Throwable tr) {
            System.err.println(msg);
            tr.printStackTrace(System.err);
        }

        @Override
        public void logVerbose(String msg) {
            if (Boolean.getBoolean("antisplit.compare.verbose")) {
                System.out.println(msg);
            }
        }
    }
}
