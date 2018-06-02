package utils;

import javax.crypto.SecretKey;
import java.io.Serializable;
import java.security.PublicKey;

public class Message implements Serializable {

    private boolean handShake = false;
    private boolean isSession = false;
    private PublicKey publicKey;
    private byte[] message;
    private int id;

    public Message(){

    }

    public Message(PublicKey publicKey){
        this.handShake = true;
        this.publicKey = publicKey;
    }

    public Message(byte[] message, boolean isSession, int id){
        this.isSession = isSession;
        this.message = message;
        this.id = id;
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
}