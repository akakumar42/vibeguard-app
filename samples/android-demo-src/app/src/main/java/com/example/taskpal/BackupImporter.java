package com.example.taskpal;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/** Restores a backup .zip the user picked. */
public class BackupImporter {

    public void restore(InputStream backup, File targetDir) throws IOException {
        try (ZipInputStream zip = new ZipInputStream(backup)) {
            ZipEntry entry;
            while ((entry = zip.getNextEntry()) != null) {
                File out = new File(targetDir, entry.getName());
                if (entry.isDirectory()) {
                    out.mkdirs();
                    continue;
                }
                out.getParentFile().mkdirs();
                try (FileOutputStream fos = new FileOutputStream(out)) {
                    byte[] buffer = new byte[8192];
                    int n;
                    while ((n = zip.read(buffer)) > 0) {
                        fos.write(buffer, 0, n);
                    }
                }
            }
        }
    }
}
