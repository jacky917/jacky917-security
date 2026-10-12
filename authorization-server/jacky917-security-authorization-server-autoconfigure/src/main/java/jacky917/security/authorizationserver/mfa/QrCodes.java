package jacky917.security.authorizationserver.mfa;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.WriterException;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

/**
 * Draws QR codes as SVG images that pages embed as {@code data:}
 * addresses, so no image is served and no desktop graphics are needed.
 * <p>
 * 把 QR code 畫成 SVG 圖片，頁面以 {@code data:} 網址嵌入；不需要另外提供圖片，
 * 也不需要桌面繪圖功能。
 *
 * @author Jacky
 * @since 2.1.0
 */
public final class QrCodes {

    private QrCodes() {
    }

    /**
     * Returns a QR code of a text as a {@code data:image/svg+xml} address.
     * <p>
     * 以 {@code data:image/svg+xml} 網址回傳文字的 QR code。
     *
     * @param text  the text, for example an {@code otpauth://} address
     *              <br>文字，例如 {@code otpauth://} 網址
     * @return the image address
     *         <br>圖片網址
     * @throws IllegalArgumentException if the text is too long for a QR code
     *         <br>若文字太長，無法放進 QR code
     */
    public static String svgDataUri(String text) {
        BitMatrix matrix;
        try {
            matrix = new QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, 0, 0,
                    Map.of(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.M, EncodeHintType.MARGIN, 4,
                            EncodeHintType.CHARACTER_SET, "UTF-8"));
        } catch (WriterException ex) {
            throw new IllegalArgumentException("The text does not fit in a QR code", ex);
        }
        int width = matrix.getWidth();
        int height = matrix.getHeight();
        StringBuilder path = new StringBuilder();
        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                if (matrix.get(x, y)) {
                    path.append('M').append(x).append(' ').append(y).append("h1v1h-1z");
                }
            }
        }
        String svg = "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 " + width + " " + height
                + "\" shape-rendering=\"crispEdges\"><rect width=\"100%\" height=\"100%\" fill=\"#fff\"/>"
                + "<path fill=\"#000\" d=\"" + path + "\"/></svg>";
        return "data:image/svg+xml;base64," + Base64.getEncoder().encodeToString(svg.getBytes(StandardCharsets.UTF_8));
    }
}
