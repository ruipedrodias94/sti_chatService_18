package utils;

import java.io.Serializable;
import java.security.*;

public class Message implements Serializable {

    //TODO: Add to signatures too
    private byte[] encryptedDataString;
    private boolean handShake;
    private PublicKey publicKey;

    public Message(){

    }

    /**
     * Handshake message type
     * @param publicKey
     */
    public Message(PublicKey publicKey){
        this.handShake = true;
        this.publicKey = publicKey;
    }

    public byte[] getEncryptedDataString() {
        return encryptedDataString;
    }

    public void setEncryptedDataString(byte[] encryptedDataString) {
        this.encryptedDataString = encryptedDataString;
    }

    public boolean isHandShake() {
        return handShake;
    }

    public void setHandShake(boolean handShake) {
        this.handShake = handShake;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }
}
