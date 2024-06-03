import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import javax.crypto.*;
import javax.crypto.spec.*;

import java.util.Base64;
import java.util.Arrays;

public class Main {

    private static final int KeyBitSize = 128;
    private static final int SaltBitSize = 128;
    private static final int NonceBitSize = 128;

    private static final int MacBitSize = 128;
    private static final int KeyDerivationIters = 1000;
    private static final int Pkcs5S2KeyBitSize = 256;

    private static final String DefaultPassword = "mR3m";

    public static void main(String[] args) {
        String encrypted_b64 = "";
        String decrypt_password = "";
        try {
            encrypted_b64 = args[0];
            System.out.println("User Input: " + encrypted_b64);
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Encrypted string not found. Exit.");
            System.out.println("Usage: java Main <Base64-Encoded AES-128-GCM String Here> [Password user defined]");
            System.exit(1);
        }
        try {
            decrypt_password = args[1];
        } catch (ArrayIndexOutOfBoundsException e) {
            decrypt_password = DefaultPassword;
            System.out.println("Use default password for cracking...");
        }

        byte[] encrypted = Base64.getDecoder().decode(encrypted_b64);
        byte[] b_salt = Arrays.copyOfRange(encrypted, 0, 16);
        byte[] b_associatedText = Arrays.copyOfRange(encrypted, 0, 16);
        byte[] b_nonce = Arrays.copyOfRange(encrypted, 16, 32);
        byte[] b_ciphertext = Arrays.copyOfRange(encrypted, 32, encrypted.length);

        byte[] b_password = dvKeyGen(decrypt_password, b_salt);
        byte[] b_decrypted = decryptAEADgcm(b_password, b_nonce, b_ciphertext, b_associatedText);

        String sfPlain = new String(b_decrypted, StandardCharsets.UTF_8);
        System.out.println("Decrypted Output: " + sfPlain);
    }

    public static byte[] dvKeyGen(String password, byte[] salt) {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, KeyDerivationIters, Pkcs5S2KeyBitSize);
            SecretKey tmp = factory.generateSecret(spec);
            return Arrays.copyOf(tmp.getEncoded(), KeyBitSize / 8);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException("Error while generating key", e);
        }
    }

    public static byte[] decryptAEADgcm(byte[] password, byte[] nonce, byte[] cipherText, byte[] associatedText) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKeySpec keySpec = new SecretKeySpec(password, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(MacBitSize, nonce);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
            cipher.updateAAD(associatedText);
            return cipher.doFinal(cipherText);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Error while decrypting", e);
        }
    }
}
