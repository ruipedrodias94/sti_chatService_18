
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import java.net.*;
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Scanner;
import java.util.Timer;
import java.util.TimerTask;


public class ChatClient implements Runnable
{  
    private SSLSocket socket                               = null;
    private Thread thread                               = null;
    private DataInputStream  console                    = null;
    private ObjectOutputStream streamOut                  = null;
    private ChatClientThread client                     = null;
    private static Signature clientSignature            = null;
    private static KeyStore clientKeystore              = null;
    private static KeyStore serverKeystore              = null;
    private static String publicAlias                   = null;
    private static KeyStore.PrivateKeyEntry accessPrivate;
    private static TrustManagerFactory trustMaterial;
    private static SSLSocketFactory SSLfactory;
    private static char[] clientPass;
    private static char[] serverPassword;
    private int period = 25000; //ms
    Message sendMessage;

    public ChatClient(String serverName, int serverPort)
    {  
        System.out.println("Establishing connection to server...");
        
        try
        {
            // Establishes SSL connection with server (name and port)
            SSLfactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            socket = (SSLSocket) SSLfactory.createSocket(serverName, serverPort);
            socket.setEnabledCipherSuites(SSLfactory.getSupportedCipherSuites());

            System.out.println("Connected to server: " + socket);
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
       Timer taskTimer = new Timer();
       taskTimer.schedule(new ChatClientThread.RemindTask(socket), 0, period);
       byte[] messagePacket = null;
       Message sendMessage;
       while (thread != null)
       {  
           try
           {
               messagePacket = console.readLine().getBytes("UTF-8");
               clientSignature.update(messagePacket);

               sendMessage = new Message(messagePacket, clientSignature.sign(), publicAlias);

               streamOut.writeObject(sendMessage);
               streamOut.flush();
           }
         
           catch(IOException ioexception)
           {  
               System.out.println("Error sending string to server: " + ioexception.getMessage());
               stop();
           } catch (SignatureException e) {
               e.printStackTrace();
           }
       }
    }


    public void handle(Message _message) throws KeyStoreException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        byte[] receivedMessage      = _message.getMessage();
        boolean checked;
        Certificate cert;
        Signature verification;

        checked = false;
        cert = serverKeystore.getCertificate(_message.getalias());
        verification = Signature.getInstance("SHA256withRSA");
        verification.initVerify(cert);
        verification.update(receivedMessage);
        checked = verification.verify(_message.getMessageSign());

        String finalMessage = null;

        if(checked)
            finalMessage = new String(receivedMessage);
        else {
            System.out.println("The message was not verified.");
            System.exit(0);
        }


        // Receives message from server
        if (finalMessage.equals(".quit"))
        {
            // Leaving, quit command
            System.out.println("Exiting...Please press RETURN to exit ...");
            stop();
        }
        else
            // else, writes message received from server to console
            System.out.println(finalMessage);
    }
    
    // Inits new client thread
    public void start() throws IOException
    {  
        console   = new DataInputStream(System.in);
        streamOut = new ObjectOutputStream(socket.getOutputStream());
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
   
    
    public static void main(String args[]) throws IOException, NoSuchAlgorithmException, KeyStoreException, CertificateException, InvalidKeyException, UnrecoverableEntryException {
        String input;
        ChatClient client = null;
        Scanner sc = new Scanner(System.in);


        if (args.length != 6)
            // Displays correct usage syntax on stdout
            System.out.println("Usage: java ChatClient host port clientJksFile clientpub");
        else
            publicAlias = args[3];

            //enter the password of the client keystore
            System.out.println("Enter the password of the keystore:");
            input = sc.nextLine();
            clientPass = input.toCharArray();

            //enter the password of the server keystore
            System.out.println("Enter the server's password:");
            input = sc.nextLine();
            serverPassword = input.toCharArray();

            //access the client keystore with client java key and his password
            clientKeystore = KeyStore.getInstance("JKS");
            clientKeystore.load(new FileInputStream(args[2]), clientPass);

            //access the server keystore with server java key and his password
            serverKeystore = KeyStore.getInstance("JKS");
            serverKeystore.load(new FileInputStream("serverpub.jks"), serverPassword);

            //accessing client private key using client password stored in the keystore and his alias
            accessPrivate = (KeyStore.PrivateKeyEntry) clientKeystore.getEntry("plainclientkeys", new KeyStore.PasswordProtection(clientPass));

            //initialize client signature using his privatekey
            clientSignature = Signature.getInstance("SHA256withRSA");
            clientSignature.initSign(accessPrivate.getPrivateKey());

            //integrity
            trustMaterial = TrustManagerFactory.getInstance("SunX509");
            trustMaterial.init(serverKeystore);

            client = new ChatClient(args[0], Integer.parseInt(args[1]));
    }
    
}

class ChatClientThread extends Thread
{  
    private SSLSocket socket   = null;
    private ChatClient       client   = null;
    private ObjectInputStream  streamIn = null;

    public ChatClientThread(ChatClient _client, SSLSocket _socket)
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
        catch(IOException ioe)
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
                client.handle((Message)streamIn.readObject());
            }
            catch(IOException ioe)
            {  
                System.out.println("Listening error: " + ioe.getMessage());
                client.stop();
            } catch (ClassNotFoundException e) {
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        }
    }

    static class RemindTask extends TimerTask {

        SSLSocket socket;

        RemindTask(SSLSocket socket){
            this.socket = socket;
        }

        public void run() {
            System.out.println("[LOG] - New handshake");
            try{
                socket.startHandshake();
            }catch(Exception e){
                System.out.println("Error starting Handshake: " + e.getMessage());
            }
        }
    }

}

