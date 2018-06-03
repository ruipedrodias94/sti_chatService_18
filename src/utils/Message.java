package utils;

import javax.crypto.SecretKey;
import java.io.Serializable;
import java.security.PublicKey;

public class Message implements Serializable {

    private boolean handShake = false;
    private boolean isSession = false;
    private PublicKey publicKey;
    private SecretKey secretKey;
    private byte[] message;

    private boolean refused = false;

    private byte[] signedMessage;
    private String alias;
    private int id;

    public Message(){

    }

    public Message(String alias){
        this.handShake = true;
        this.setAlias(alias);
    }

    public Message(PublicKey publicKey){
        this.handShake = true;
        this.publicKey = publicKey;
    }

    public Message(byte[] message, byte[] signedMessage){
        this.signedMessage = signedMessage;
        this.message = message;
    }

    public Message(byte[] message, boolean isSession, int id){
        this.isSession = isSession;
        this.message = message;
        this.id = id;
    }

    public Message(byte[] message, boolean isSession){
        this.isSession = isSession;
        this.message = message;
    }

    public Message(boolean refused){
        this.setRefused(refused);
    }

    public boolean isHandShake() {
        return handShake;
    }

    public void setHandShake(boolean handShake) {
        this.handShake = handShake;
    }

    public boolean isSession() {
        return isSession;
    }

    public void setSession(boolean session) {
        isSession = session;
    }


    public PublicKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public byte[] getMessage() {
        return message;
    }

    public void setMessage(byte[] message) {
        this.message = message;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public SecretKey getSecretKey() {
        return secretKey;
    }

    public void setSecretKey(SecretKey secretKey) {
        this.secretKey = secretKey;
    }


    public String getAlias() {
        return alias;
    }

    public void setAlias(String alias) {
        this.alias = alias;
    }

    public byte[] getSignedMessage() {
        return signedMessage;
    }

    public void setSignedMessage(byte[] signedMessage) {
        this.signedMessage = signedMessage;
    }

    public boolean isRefused() {
        return refused;
    }

    public void setRefused(boolean refused) {
        this.refused = refused;
    }
}