import com.itextpdf.commons.bouncycastle.asn1.tsp.ITSTInfo;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.signatures.PdfPKCS7;
import com.itextpdf.signatures.SignatureUtil;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.operator.OperatorCreationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.List;

public class PDFVerifierTSA {

    private static final Logger logger = LoggerFactory.getLogger(PDFVerifierTSA.class);

    static {
        // Añadir el proveedor de Bouncy Castle
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

    public static String getTimestampInfo(String pdfPath) throws IOException, GeneralSecurityException, OperatorCreationException, CertificateException {
        PdfDocument pdfDoc = new PdfDocument(new PdfReader(pdfPath));
        SignatureUtil signUtil = new SignatureUtil(pdfDoc);
        List<String> signatureNames = signUtil.getSignatureNames();

        for (String name : signatureNames) {
            PdfPKCS7 pkcs7 = signUtil.readSignatureData(name);
            Calendar timestampDate = pkcs7.getTimeStampDate();
            if (timestampDate != null) {
                SimpleDateFormat sdf = new SimpleDateFormat("dd-MM-yyyy HH:mm:ss");
                String timestampInfo = "Timestamp generated on: " + sdf.format(timestampDate.getTime());

                // Obtener la información del ITSTInfo
                ITSTInfo timeStampTokenInfo = pkcs7.getTimeStampTokenInfo();

                if (timeStampTokenInfo != null) {
                    // Obtener el certificado TSA
                    X509Certificate tsaCert = (X509Certificate) pkcs7.getTimestampCertificates()[0];
                    JcaX509CertificateHolder tsaCertHolder = new JcaX509CertificateHolder(tsaCert);

                    // Verificar la validez del certificado en el momento de la generación del sello de tiempo
                    boolean isTsaCertValidAtGeneration = tsaCert.getNotBefore().before(timestampDate.getTime()) && tsaCert.getNotAfter().after(timestampDate.getTime());

                    // Obtener la fecha de vencimiento del certificado TSA
                    String tsaCertExpiryDate = sdf.format(tsaCert.getNotAfter());

                    timestampInfo += "\nTSA certificate was valid at the time of timestamp generation: " + isTsaCertValidAtGeneration;
                    timestampInfo += "\nTSA certificate is valid until: " + tsaCertExpiryDate;

                    return timestampInfo;
                }
            }
        }
        return null;
    }

    public static void main(String[] args) {
        try {
            // Proporciona la ruta correcta al archivo PDF
            String pdfPath = "/Users/brandonluismenesessolorzano/Downloads/F_Semana+18+-+PDF_ZWYSTB(22).pdf";  // Asegúrate de que esta ruta sea correcta
            String timestampInfo = getTimestampInfo(pdfPath);
            if (timestampInfo != null) {
                logger.info(timestampInfo);
            } else {
                logger.info("The document does not have a timestamp.");
            }
        } catch (IOException | GeneralSecurityException | OperatorCreationException e) {
            logger.error("Error verifying the timestamp.", e);
        }
    }
}


