import org.junit.BeforeClass;
import org.junit.Test;

import java.io.UnsupportedEncodingException;

import static org.junit.Assert.assertEquals;

/**
 * @author Sergiy Levchynskyi
 */

public class EncryptorTest {

    private static final String DATA = "Some data";
    private static byte[] RAW_KEY;
    private static Encryptor encryptor;

    @BeforeClass
    public static void init() throws UnsupportedEncodingException {
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
}