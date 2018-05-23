package utils;


import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
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
     */
    public byte[] encryptMessage(byte[] messageToBeEncrypted, PublicKey publicKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        this.cipher = Cipher.getInstance("RSA/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] cipherText = cipher.doFinal(messageToBeEncrypted);
        return cipherText;
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
