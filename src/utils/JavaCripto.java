package utils;


import javax.crypto.*;
import java.security.*;

/**
 * Class to create and put all the functions used in criptography
 *  - Key creations
 *  - Certificates
 *  - Encrypt messages
 *  - Etc..
 */

public class JavaCripto {

    private KeyPairGenerator keyPairGenerator;
    private Cipher cipher;
    private Signature signature;

    public JavaCripto(){

    }

    /**
     * Function to initiate and generate a key pair for both server and client
     * @param keySize
     * @return
     * @throws NoSuchAlgorithmException
     */
    public KeyPair generateKeyPar(int keySize) throws NoSuchAlgorithmException {
        this.keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keySize);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        return keyPair;
    }

    /**
     * Function to encrypt messages
     * @param messageToBeEncrypted
     * @param publicKey
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public byte[] encryptMessage(byte[] messageToBeEncrypted, Key publicKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        this.cipher = Cipher.getInstance("RSA");
        System.out.println("Entras aqui?");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encrypted = cipher.doFinal(messageToBeEncrypted);
        return encrypted;
    }

    /**
     * Function to decrypt messages
     * @param messageToBeDecrypted
     * @param privateKey
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public byte[] decryptMessage(byte[] messageToBeDecrypted, Key privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        this.cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decrypted = cipher.doFinal(messageToBeDecrypted);
        return decrypted;
    }


    public KeyPairGenerator getKeyPairGenerator() {
        return keyPairGenerator;
    }

    public void setKeyPairGenerator(KeyPairGenerator keyPairGenerator) {
        this.keyPairGenerator = keyPairGenerator;
    }

    public Cipher getCipher() {
        return cipher;
    }

    public void setCipher(Cipher cipher) {
        this.cipher = cipher;
    }

    public Signature getSignature() {
        return signature;
    }

    public void setSignature(Signature signature) {
        this.signature = signature;
    }
}
