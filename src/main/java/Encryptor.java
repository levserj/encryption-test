import org.apache.log4j.Logger;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.Provider;
import java.security.SecureRandom;

/**
 * @author Sergiy Levchynskyi
 */

public class Encryptor {
    private static final Logger LOGGER = Logger.getLogger(Encryptor.class);
    private static final String ALGORITHM_1 = "AES/GCM/NoPadding";
    private static final String ALGORITHM_2 = "AES/ECB/PKCS5Padding";
    private static final int TAG_LENGTH_BIT = 128;
    private static final int IV_LENGTH_BYTE = 12;

    private final SecureRandom secureRandom;
    private final Provider provider;
    private Cipher cipher;

    public Encryptor() {
        this(new SecureRandom(), null);
    }

    public Encryptor(SecureRandom secureRandom) {
        this(secureRandom, null);
    }

    public Encryptor(SecureRandom secureRandom, Provider provider) {
        this.secureRandom = secureRandom;
        this.provider = provider;
    }


    public byte[] encrypt(byte[] rawEncryptionKey, byte[] rawData) {
        if (rawEncryptionKey.length < 16) {
            throw new IllegalArgumentException("key length must be longer than 16 byte");
        }

        try {
            byte[] iv = new byte[IV_LENGTH_BYTE];
            secureRandom.nextBytes(iv);

            byte[] encrypted;
            final Cipher cipher = getCipher(ALGORITHM_1);

            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(rawEncryptionKey, "AES"), new GCMParameterSpec(TAG_LENGTH_BIT, iv));
            encrypted = cipher.doFinal(rawData);

            ByteBuffer byteBuffer = ByteBuffer.allocate(1 + iv.length + encrypted.length);
            byteBuffer.put((byte) iv.length);
            byteBuffer.put(iv);
            byteBuffer.put(encrypted);
            return byteBuffer.array();
        } catch (Exception e) {
            LOGGER.error("Failed to encrypt. Exception : " + e.getMessage());
        }
        return null;
    }


    public byte[] decrypt(byte[] rawEncryptionKey, byte[] encryptedData) {
        try {
            ByteBuffer byteBuffer = ByteBuffer.wrap(encryptedData);

            int ivLength = byteBuffer.get();
            byte[] iv = new byte[ivLength];
            byteBuffer.get(iv);
            byte[] encrypted = new byte[byteBuffer.remaining()];
            byteBuffer.get(encrypted);

            final Cipher cipher = getCipher(ALGORITHM_1);
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(rawEncryptionKey, "AES"), new GCMParameterSpec(TAG_LENGTH_BIT, iv));

            return cipher.doFinal(encrypted);
        } catch (Exception e) {
            LOGGER.error("Failed to decrypt. Exception : " + e.getMessage());
        }
        return null;
    }

    public InputStream getInputStreamAndDecrypt(byte[] rawEncryptionKey, InputStream is) {
        final Cipher cipher = getCipher(ALGORITHM_2);
        try {
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(rawEncryptionKey, "AES"));
            return new CipherInputStream(is, cipher);
        } catch (InvalidKeyException e) {
            LOGGER.error("Failed to encrypt. Exception : " + e.getMessage());
        }
        return null;
    }

    public OutputStream getOutputStreamAndEncrypt(byte[] rawEncryptionKey, OutputStream os) {
        final Cipher cipher = getCipher(ALGORITHM_2);
        try {
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(rawEncryptionKey, "AES"));
            return new CipherOutputStream(os, cipher);
        } catch (InvalidKeyException e) {
            LOGGER.error("Failed to decrypt. Exception : " + e.getMessage());
        }
        return null;
    }

    private Cipher getCipher(String algoritm) {
        if (cipher == null) {
            try {
                if (provider != null) {
                    cipher = Cipher.getInstance(algoritm, provider);
                } else {
                    cipher = Cipher.getInstance(algoritm);
                }
            } catch (Exception e) {
                LOGGER.error("could not get cipher instance. Exception : " + e.getMessage());
            }
        }
        return cipher;
    }
}
