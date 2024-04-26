import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;


public class KmsJava {
    public static void main(String[] args) throws Exception {
        CryptoUtil cryptoUtil = new AesEncryption();
        String key = cryptoUtil.generateKey();
        String plainText = "Hello, security Java!";
        String encryptedText = cryptoUtil.encrypt(plainText, key);
        String decryptedText = cryptoUtil.decrypt(encryptedText, key);
        assert plainText.equals(decryptedText):"Error";
        System.out.println("Key: " + key);
        System.out.println("Encrypted text: " + encryptedText);
        System.out.println("Decrypted text: " + decryptedText);
    }
}

interface CryptoUtil {
    String generateKey() throws Exception;
    String encrypt(String plainText, String encryptedKey) throws Exception;
    String decrypt(String encryptedText, String encryptedKey) throws Exception;
}

class AesEncryption implements CryptoUtil {
    private static final String ALORITHM = "AES";
    private static final String DEFAULT_KEY = "";
    private SecretKey masterKey;

    public AesEncryption() {
        this.masterKey = buildKey();
    }

    @Override
    public String generateKey() throws Exception {
        String plainSecretKey = secretKeyToStringKey(buildKey());
        return encryptByKey(plainSecretKey, masterKey);
    }

    @Override
    public String encrypt(String plainText, String encryptedKey) throws Exception {
        SecretKey secretKey = getDataKey(encryptedKey);
        return encryptByKey(plainText, secretKey);
    }

    @Override
    public String decrypt(String encryptedText, String encryptedKey) throws Exception {
        SecretKey secretKey = getDataKey(encryptedKey);
        return decryptedByKey(encryptedText, secretKey);
    }

    private String secretKeyToStringKey(SecretKey secretKey) {
        return bytesToString(secretKey.getEncoded());
    }

    private String bytesToString(byte[] encodedKey) {
        return Base64.getEncoder().encodeToString(encodedKey);
    }

    private SecretKey buildKey() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(ALORITHM);
            keyGenerator.init(256);
            return keyGenerator.generateKey();
        } catch (Exception e) {
            return new SecretKeySpec(Base64.getDecoder().decode(DEFAULT_KEY), ALORITHM);
        }
    }
    
    private String encryptByKey(String plainSecretKey, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(plainSecretKey.getBytes());
        return bytesToString(encryptedBytes);
    }

    private SecretKeySpec getDataKey(String encryptedKey) throws Exception {
        String encodedKey = decryptedByKey(encryptedKey, masterKey);
        return new SecretKeySpec(Base64.getDecoder().decode(encodedKey), ALORITHM);
    }

    private String decryptedByKey(String encryptedText, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedTextBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
        return new String(decryptedTextBytes);
    }
}
