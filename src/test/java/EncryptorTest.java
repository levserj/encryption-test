import org.apache.commons.io.IOUtils;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.security.NoSuchAlgorithmException;

import static org.junit.Assert.assertEquals;

/**
 * @author Sergiy Levchynskyi
 */

public class EncryptorTest {

    private static final String DATA = "Some data";
    private static byte[] RAW_KEY;
    private static Encryptor encryptor;

    @BeforeClass
    public static void init() throws UnsupportedEncodingException, NoSuchPaddingException, NoSuchAlgorithmException {
        RAW_KEY = "THEMOSTSECRETKEY".getBytes("UTF-8");
        encryptor = new Encryptor();
    }

    @Test
    public void encryptionTest() throws UnsupportedEncodingException {
        byte[] rowData = DATA.getBytes("UTF-8");
        byte[] encrypted = encryptor.encrypt(RAW_KEY, rowData);
        byte[] decrypted = encryptor.decrypt(RAW_KEY, encrypted);
        assertEquals(DATA, new String(decrypted));
    }

    @Test
    public void encryptionWithStreamsTest() throws IOException, InterruptedException {
        byte[] rowData = DATA.getBytes("UTF-8");
        File tmp = File.createTempFile("tmpEncryptedByteArray", ".txt");
        tmp.deleteOnExit();
        OutputStream encryptedOutputStream = encryptor.getOutputStreamAndEncrypt(RAW_KEY, new FileOutputStream(tmp));
        encryptedOutputStream.write(rowData);
        encryptedOutputStream.flush();
        encryptedOutputStream.close();
        InputStream decryptedInputStream = encryptor.getInputStreamAndDecrypt(RAW_KEY, new FileInputStream(tmp));
        byte[] decrypted = IOUtils.toByteArray(decryptedInputStream);
        assertEquals(DATA, new String(decrypted));
        decryptedInputStream.close();
    }
}
