package com.abdurazaaqmohammed.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class FileUtils {
    public static InputStream getInputStream(File file) throws IOException {
        return new FileInputStream(file);
    }

    public static OutputStream getOutputStream(File file) throws IOException {
        return new FileOutputStream(file);
    }
}
