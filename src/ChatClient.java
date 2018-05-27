
import utils.JavaCripto;
import utils.Message;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.net.*;
import java.io.*;
import java.security.*;


//TODO: Transformar todas as streams de inputs para objects

public class ChatClient implements Runnable
{  
    private Socket socket              = null;
    private Thread thread              = null;
    private DataInputStream console = null;
    private ObjectOutputStream streamOut = null;
    private ChatClientThread client    = null;


    private PublicKey serverPublicKey;

    private KeyPair clientKeyPair;

    private JavaCripto javaCripto;



    public ChatClient(String serverName, int serverPort) throws NoSuchPaddingException, NoSuchProviderException {
        System.out.println("Establishing connection to server...");
        
        try
        {
            // Establishes connection with server (name and port)
            socket = new Socket(serverName, serverPort);
            System.out.println("Connected to server: " + socket);

            this.javaCripto = new JavaCripto();

            this.clientKeyPair = javaCripto.generateKeyPair();

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
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

    }
    
   public void run()
   {  
       while (thread != null)
       {  
           try
           {  
               // Sends message from console to server
               Message newMessage;
               String stringToEncrypt = console.readLine();

               //Encrypt the data and send them in a message object
               byte[] dataToEncrypt = this.javaCripto.encrypt(clientKeyPair.getPrivate(), stringToEncrypt);

               newMessage = new Message(dataToEncrypt);

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

        if (message.isHandShake()){

            System.out.println("Handshake from server. Public key received");
            System.out.println(message.getPublicKey());
            this.serverPublicKey = message.getPublicKey();

        }
        else {

            byte[] decryptedMessage = this.javaCripto.decrypt(serverPublicKey, message.getEncryptedDataByte());

            System.out.println(new String(decryptedMessage));
        }
    }
    
    /*public void handle(String msg)
    {  
        // Receives message from server
        if ( msg.equals(".quit"))
        {  
            // Leaving, quit command
            System.out.println("Exiting...Please press RETURN to exit ...");
            stop();
        }
        else
            // else, writes message received from server to console
            System.out.println("Recebe alguma coisa?");
            System.out.println(msg);
    }*/
    
    // Inits new client thread
    public void start() throws IOException
    {
        console   = new DataInputStream(System.in);
        streamOut = new ObjectOutputStream(socket.getOutputStream());

        Message newHandShake = new Message(this.clientKeyPair.getPublic());

        streamOut.writeObject(newHandShake);
        streamOut.flush();

        if (newHandShake.isHandShake()){
            System.out.println("The client made an handshake!");
        }

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
   
    
    public static void main(String args[]) throws NoSuchPaddingException, NoSuchProviderException {
        ChatClient client = null;
        if (args.length != 2)
            // Displays correct usage syntax on stdout
            System.out.println("Usage: java ChatClient host port");
        else
            // Calls new client
            client = new ChatClient(args[0], Integer.parseInt(args[1]));
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
                client.handle((Message) streamIn.readObject());
            }
            catch(Exception ioe)
            {  
                System.out.println("Listening error: " + ioe.getMessage());
                client.stop();

            }
        }
    }
}

