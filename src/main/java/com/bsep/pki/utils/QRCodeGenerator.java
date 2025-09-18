package com.bsep.pki.utils;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import lombok.NoArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.Base64;

@NoArgsConstructor
@Component
public class QRCodeGenerator {
    public static String generateQRCode(String barcodeText, int width, int height) throws Exception {
        QRCodeWriter qrCodeWriter = new QRCodeWriter();
        var bitMatrix = qrCodeWriter.encode(barcodeText, BarcodeFormat.QR_CODE, width, height);
        try (var baos = new java.io.ByteArrayOutputStream()) {
            MatrixToImageWriter.writeToStream(bitMatrix, "PNG", baos);
            byte[] bytes = baos.toByteArray();
            String base64 = Base64.getEncoder().encodeToString(bytes);
            return "data:image/png;base64," + base64;
        }
    }
}

