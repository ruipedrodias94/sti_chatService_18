
import javax.net.ssl.TrustManagerFactory;
import java.net.*;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Scanner;


public class ChatClient implements Runnable
{  
    private Socket socket                   = null;
    private Thread thread                   = null;
    private DataInputStream  console        = null;
    private DataOutputStream streamOut      = null;
    private ChatClientThread client         = null;
    private static Signature mySignature    = null;
    private static KeyStore myKeystore      = null;
    private static KeyStore keyServer       = null;
    private static String publicAlias       = null;

    public ChatClient(String serverName, int serverPort)
    {  
        System.out.println("Establishing connection to server...");
        
        try
        {
            // Establishes connection with server (name and port)
            socket = new Socket(serverName, serverPort);
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
       while (thread != null)
       {  
           try
           {  
               // Sends message from console to server
               streamOut.writeUTF(console.readLine());
               streamOut.flush();
           }
         
           catch(IOException ioexception)
           {  
               System.out.println("Error sending string to server: " + ioexception.getMessage());
               stop();
           }
       }
    }
    
    
    public void handle(String msg)
    {  
        // Receives message from server
        if (msg.equals(".quit"))
        {  
            // Leaving, quit command
            System.out.println("Exiting...Please press RETURN to exit ...");
            stop();
        }
        else
            // else, writes message received from server to console
            System.out.println(msg);
    }
    
    // Inits new client thread
    public void start() throws IOException
    {  
        console   = new DataInputStream(System.in);
        streamOut = new DataOutputStream(socket.getOutputStream());
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

            System.out.println("Enter the password of the keystore:");
            input = sc.nextLine();
            char[] keystorePass = input.toCharArray();

            System.out.println("Enter the server's password:");
            input = sc.nextLine();
            char[] serverPassword = input.toCharArray();

            myKeystore = KeyStore.getInstance("JKS");
            FileInputStream fileInputStream = new FileInputStream(args[2]);
            myKeystore.load(fileInputStream, keystorePass);
            fileInputStream.close();

            KeyStore.ProtectionParameter keyPass = new KeyStore.PasswordProtection(keystorePass);
            KeyStore.PrivateKeyEntry privKeyEntry = (KeyStore.PrivateKeyEntry) myKeystore.getEntry("plainclientkeys", keyPass);
            PrivateKey privateKey = privKeyEntry.getPrivateKey();

            mySignature = Signature.getInstance("SHA256withRSA");
            mySignature.initSign(privateKey);

            keyServer = KeyStore.getInstance("JKS");
            keyServer.load(new FileInputStream("serverpub.jks"), serverPassword);

            TrustManagerFactory trustManager = TrustManagerFactory.getInstance("SunX509");
            trustManager.init(keyServer);

            client = new ChatClient(args[0], Integer.parseInt(args[1]));
    }
    
}

class ChatClientThread extends Thread
{  
    private Socket           socket   = null;
    private ChatClient       client   = null;
    private DataInputStream  streamIn = null;

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
            streamIn  = new DataInputStream(socket.getInputStream());
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
                client.handle(streamIn.readUTF());
            }
            catch(IOException ioe)
            {  
                System.out.println("Listening error: " + ioe.getMessage());
                client.stop();
            }
        }
    }
}

