package utils;

import java.io.Serializable;
import java.security.*;

public class Message implements Serializable {

    private byte[] encryptedDataString;
    private boolean handShake;
    private PublicKey publicKey;
    private  String simpleString;

    public Message(byte[] encryptedDataString){
        this.encryptedDataString = encryptedDataString;
    }

    public Message(String simpleString){
        this.setSimpleString(simpleString);
    }

    /**
     * Handshake message type
     * @param publicKey
     */
    public Message(PublicKey publicKey){
        this.handShake = true;
        this.publicKey = publicKey;
    }

    public Message() {

    }

    public byte[] getEncryptedDataByte() {
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

    public String getSimpleString() {
        return simpleString;
    }

    public void setSimpleString(String simpleString) {
        this.simpleString = simpleString;
    }
}