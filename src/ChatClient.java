
import utils.JavaCripto;
import utils.Message;

import javax.crypto.*;
import java.net.*;
import java.io.*;
import java.security.*;
import java.util.Base64;
import java.util.Timer;
import java.util.TimerTask;


public class ChatClient implements Runnable
{
    private Socket socket              = null;
    private Thread thread              = null;
    private DataInputStream console = null;
    private ObjectOutputStream streamOut = null;
    private ChatClientThread client    = null;


    //KEYS
    private PublicKey serverPublicKey;
    private static SecretKey sessionKey;
    private KeyPair clientKeyPair;

    private static JavaCripto javaCripto;


    private static String alias;
    public static String password;

    private Signature signature;

    private int periodTimer = 20000;
    private Timer timer;



    public ChatClient(String serverName, int serverPort) throws Exception {
        System.out.println("Establishing connection to server...");

        try
        {
            // Establishes connection with server (name and port)
            socket = new Socket(serverName, serverPort);
            System.out.println("Connected to server: " + socket);

            javaCripto = new JavaCripto();

            sessionKey = javaCripto.generateSecretKey();

            System.out.println("[USERNAME] - " + alias);
            System.out.println("[PASSWORD] - " + password);

            clientKeyPair = javaCripto.getKeyPairFromKeyStore(alias, password);

            signature = javaCripto.createSignature(clientKeyPair.getPrivate());

            start();
        }

        catch(UnknownHostException uhe)
        {
            // Host unkwnown
            System.out.println("Error establishing connection - host unknown: " + uhe.getMessage());
        }

        catch(IOException ioexception)
        {
            // Other error establishing connection
            System.out.println("Error establishing connection - unexpected exception: " + ioexception.getMessage());
        }

    }

    public void run()
    {

        timer = new Timer();
        timer.schedule(new TimerTask() {

            @Override
            public void run() {
                try {
                    renewSecretSessionKey();
                    System.out.println("[KEYS RENEWED]");
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }, 20000, periodTimer);



        while (thread != null)
        {
            try
            {
                // Sends message from console to server
                Message newMessage;
                String stringToEncrypt = console.readLine();

                //Encrypt the data and send them in a message object
                byte[] dataToEncrypt = javaCripto.encryptMessage(sessionKey, stringToEncrypt.getBytes());
                signature.update(dataToEncrypt);
                byte[] signData = signature.sign();

                newMessage = new Message(dataToEncrypt, signData);

                streamOut.writeObject(newMessage);
                streamOut.flush();

            }

            catch(Exception ioexception) {
                System.out.println("Error sending string to server: " + ioexception.getMessage());
                stop();
            }
        }
    }


    public void handle(Message message) throws Exception {

        if (message.isRefused()){
            System.out.println("CONECTION REFUSED USER UNAUTHORIZED");
            System.out.println("Exiting...Please press RETURN to exit ...");
            stop();

        } else {

            System.out.println("[USER HAS LOGGED IN]");
            if (message.isHandShake()){

                this.serverPublicKey = message.getPublicKey();

                renewSecretSessionKey();
            }

            else {

                byte[] decryptedMessage = javaCripto.decryptMessage(sessionKey, message.getMessage());

                if (new String(decryptedMessage).equals(".quit")){
                    System.out.println("Exiting...Please press RETURN to exit ...");
                    stop();
                } else {
                    System.out.println("[" + message.getId()+"] - " + new String(decryptedMessage));
                }

            }
        }




    }

    public void renewSecretSessionKey() throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, IOException {
        byte[] messageEnc = sessionKey.getEncoded();

        byte[] messageEncrypted = javaCripto.encryptSessionKey(serverPublicKey, messageEnc);

        Message message = new Message(messageEncrypted, true);

        streamOut.writeObject(message);
        streamOut.flush();
    }


    // Inits new client thread
    public void start() throws Exception
    {
        console   = new DataInputStream(System.in);
        streamOut = new ObjectOutputStream(socket.getOutputStream());


        //SEND THE PUBLIC KEY OF THE CLIENT TO THE SERVER
        Message handshakeMessage = new Message(alias);

        streamOut.writeObject(handshakeMessage);
        streamOut.flush();

        if (thread == null)
        {
            client = new ChatClientThread(this, socket);
            thread = new Thread(this);
            thread.start();
        }
    }

    // Stops client thread
    public void stop()
    {
        if (thread != null)
        {
            thread.stop();
            thread = null;
            timer.cancel();
            timer.purge();
        }
        try
        {
            if (console   != null)  console.close();
            if (streamOut != null)  streamOut.close();
            if (socket    != null)  socket.close();

        }

        catch(IOException ioe)
        {
            System.out.println("Error closing thread..."); }
        client.close();
        client.stop();
    }



    public static void main(String args[]) throws Exception {
        ChatClient client = null;
        if (args.length != 4)
            // Displays correct usage syntax on stdout
            System.out.println("Usage: java ChatClient host port");
        else
            // Calls new client
        {

            alias = args[2];
            password = args[3];

            client = new ChatClient(args[0], Integer.parseInt(args[1]));
        }
    }

}

class ChatClientThread extends Thread
{
    private Socket           socket   = null;
    private ChatClient       client   = null;
    private ObjectInputStream  streamIn = null;

    public ChatClientThread(ChatClient _client, Socket _socket)
    {
        client   = _client;
        socket   = _socket;
        open();
        start();
    }

    public void open()
    {
        try
        {
            streamIn  = new ObjectInputStream(socket.getInputStream());
        }
        catch(Exception ioe)
        {
            System.out.println("Error getting input stream: " + ioe);
            client.stop();
        }
    }

    public void close()
    {
        try
        {
            if (streamIn != null) streamIn.close();
        }

        catch(IOException ioe)
        {
            System.out.println("Error closing input stream: " + ioe);
        }
    }

    public void run()
    {
        while (true)
        {   try
        {
            Thread.sleep(800);
            client.handle((Message)streamIn.readObject());
        }
        catch(IOException ioe)
        {
            System.out.println("Listening error: " + ioe.getMessage());
            client.stop();
        }
        catch(ClassNotFoundException e){

        } catch (Exception e) {
            e.printStackTrace();
        }
        }
    }
}
