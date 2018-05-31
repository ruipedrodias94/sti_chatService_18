import java.io.Serializable;
import java.security.*;

public class Message implements Serializable {

    private byte[] encryptedDataString;
    private boolean handShake;
    private PublicKey publicKey;
    private  String simpleString;
    private byte[] message;
    private byte[] messageSign;
    private String alias;

    Message(byte[] _message, byte[] _messageSign, String alias){
        this.message = _message;
        this.messageSign = _messageSign;
        this.alias = alias;
    }


    public Message() {

    }

    public byte[] getMessage() {
        return this.message;
    }
    public byte[] getMessageSign() {
        return this.messageSign;
    }
    public String getalias() {
        return this.alias;
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

    public void setMessage(byte[] _message) {
        this.message = _message;
    }
    public void setMessageSign(byte[] _messageSign) {
        this.messageSign = _messageSign;
    }
    public void setalias(String _alias) {
        this.alias = _alias;
    }

}