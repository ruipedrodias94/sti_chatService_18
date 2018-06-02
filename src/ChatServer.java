
import utils.JavaCripto;
import utils.Message;

import javax.crypto.*;
import java.net.*;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Scanner;


public class ChatServer implements Runnable

{  
	private ChatServerThread clients[] = new ChatServerThread[20];
	private ServerSocket server_socket = null;
	private Thread thread = null;
	private int clientCount = 0;


	// CRIPTO
	private SecretKey secretKey;
	private JavaCripto javaCripto = null;
	private KeyStore keyStore;
	private KeyStore.SecretKeyEntry secretKeyEntry;

    	public void run()
    	{
        	while (thread != null)
        	{
            		try
            		{
                		// Adds new thread for new client
                		System.out.println("Waiting for a client ...");
                		addThread(server_socket.accept());
            		}
            		catch(IOException ioexception)
            		{
                		System.out.println("Accept error: " + ioexception); stop();
            		}
        	}
    	}

   	    public void start()
    	{
        	if (thread == null)
        	{
            		// Starts new thread for client
            		thread = new Thread(this);
            		thread.start();
        	}
    	}

	public ChatServer(int port) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableEntryException {
		try
		{
			// Binds to port and starts server
			System.out.println("Binding to port " + port);
			server_socket = new ServerSocket(port);
			System.out.println("Server started: " + server_socket);


			javaCripto = new JavaCripto();

			//GETTING THE PASS TO KEYSTORE
			System.out.println("Enter the password to access the keystore: ");
			Scanner sc = new Scanner(System.in);
			String input = sc.nextLine();
			char[] serverPass = input.toCharArray();

			//LOGIN TO KEYSTORE
			keyStore = KeyStore.getInstance("jceks");
			keyStore.load(new FileInputStream("keystore.jks"), serverPass);

			//ACCESS THE SECRETKEY
			secretKeyEntry = (KeyStore.SecretKeyEntry) keyStore.getEntry("secretKey", new KeyStore.PasswordProtection(serverPass));
			secretKey = secretKeyEntry.getSecretKey();

			System.out.println("Logado com sucesso!");

			start();

		}
		catch(IOException ioexception)
		{
			// Error binding to port
			System.out.println("Binding error (port=" + port + "): " + ioexception.getMessage());

		}
    	}

    	public void stop()
    	{  
        	if (thread != null)
        	{
            		// Stops running thread for client
            		thread.stop(); 
            		thread = null;
        	}
    	}
   
    	private int findClient(int ID)
    	{  
        	// Returns client from id
        	for (int i = 0; i < clientCount; i++)
            		if (clients[i].getID() == ID)
                		return i;
        	return -1;
    	}
    
    	public synchronized void handle(int ID, Message message) throws Exception {
        	/*if (input.equals(".quit"))
            	{  
                	int leaving_id = findClient(ID);
                	// Client exits
                	clients[leaving_id].send(".quit");
                	// Notify remaing users
                	for (int i = 0; i < clientCount; i++)
                    		if (i!=leaving_id)
                        		clients[i].send("Client " +ID + " exits..");
                	remove(ID);
            	}
        	else
            		// Brodcast message for every other client online
            		for (int i = 0; i < clientCount; i++)
                		clients[i].send(ID + ": " + input);   */

				int id = findClient(ID);

				System.out.println("ENTRAS");

				byte[] decryptedMessage = javaCripto.decrypt(secretKey, message.getEncryptedDataByte());

				System.out.println("Desencriptou com sucesso, a enviar: " + new String(decryptedMessage));

				byte[] newEncrypted = javaCripto.encrypt(secretKey, new String(decryptedMessage));

				Message newMessage = new Message(newEncrypted);
						//new Message(newEncrypted);

				for (int i = 0; i < clientCount; i++) {
					clients[i].send(newMessage);
				}
    	}
    
    	public synchronized void remove(int ID)
    	{  
        	int pos = findClient(ID);
      
       	 	if (pos >= 0)
        	{  
            		// Removes thread for exiting client
            		ChatServerThread toTerminate = clients[pos];
            		System.out.println("Removing client thread " + ID + " at " + pos);
            		if (pos < clientCount-1)
                		for (int i = pos+1; i < clientCount; i++)
                    			clients[i-1] = clients[i];
            		clientCount--;
         
            		try
            		{  
                		toTerminate.close(); 
            		}
         
            		catch(IOException ioe)
            		{  
                		System.out.println("Error closing thread: " + ioe); 
            		}
         
            		toTerminate.stop(); 
        	}
    	}
    
    	private void addThread(Socket socket)
    	{  
    	    	if (clientCount < clients.length)
        	{  
            		// Adds thread for new accepted client
            		System.out.println("Client accepted: " + socket);
            		clients[clientCount] = new ChatServerThread(this, socket);
         
           		try
            		{  
                		clients[clientCount].open(); 
                		clients[clientCount].start();

                		//The addThread will be the "handshake" so we sent a type of message, only with the public key
                        /*Message handshakeMessage = new Message(this.keyPair.getPublic());

                		clients[clientCount].sendPublicKeyToClient(handshakeMessage);

                		clientCount++;*/
            		}
            		catch(IOException ioe)
            		{  
               			System.out.println("Error opening thread: " + ioe); 
            		}
       	 	}
        	else
            		System.out.println("Client refused: maximum " + clients.length + " reached.");
    	}


    
    
	public static void main(String args[]) throws UnrecoverableEntryException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
        	ChatServer server = null;
        
        	if (args.length != 1)
            		// Displays correct usage for server
            		System.out.println("Usage: java ChatServer port");
        	else
            		// Calls new server
            		server = new ChatServer(Integer.parseInt(args[0]));
    	}


}

class ChatServerThread extends Thread
{
    private ChatServer       server    = null;
    private Socket           socket    = null;
    private int              ID        = -1;
    private ObjectInputStream  streamIn  =  null;
    private ObjectOutputStream streamOut = null;


    public ChatServerThread(ChatServer _server, Socket _socket)
    {
        super();
        server = _server;
        socket = _socket;
        ID     = socket.getPort();
    }

    // Sends message to client

    public void send(Message msg)
    {   
        try
        {  
            streamOut.writeObject(msg);

            streamOut.flush();
        }

        catch(IOException ioexception)
        {
            System.out.println(ID + " ERROR sending message: " + ioexception.getMessage());
            server.remove(ID);
            stop();
        }
    }

    // Gets id for client
    public int getID()
    {
        return ID;
    }

    // Runs thread
    public void run()
    {
        System.out.println("Server Thread " + ID + " running.");

        while (true)
        {
            try

            {  
                server.handle(ID, (Message) streamIn.readObject());
            }
         
            catch(Exception ioe)
            {  

                System.out.println(ID + " ERROR reading: " + ioe.getMessage());
                server.remove(ID);
                stop();

            }
		}
    }

    /**
     * Test function to send the public key of the server to the client on first connect
     *
     * @param message
     */
    public void sendSecretKeyToClient(Message message){

        try {

            streamOut.writeObject(message);
            streamOut.flush();
            System.out.println("SecretKey key enviada para o cliente " + getID());

        } catch (IOException e) {

            e.printStackTrace();
        }
    }


    // Opens thread
    public void open() throws IOException

    {  
        streamIn = new ObjectInputStream(new BufferedInputStream(socket.getInputStream()));
                //new DataInputStream(new BufferedInputStream(socket.getInputStream()));
        streamOut = new ObjectOutputStream(new BufferedOutputStream(socket.getOutputStream()));
                //new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()));

    }

    // Closes thread
    public void close() throws IOException
    {
        if (socket != null)    socket.close();
        if (streamIn != null)  streamIn.close();
        if (streamOut != null) streamOut.close();
    }

}


