
import javax.net.ssl.TrustManagerFactory;
import java.net.*;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Scanner;


public class ChatServer implements Runnable
{  
	private ChatServerThread clients[] = new ChatServerThread[20];
	private ServerSocket server_socket = null;
	private Thread thread = null;
	private int clientCount = 0;

	private static String aliasPub = null;

	private static Signature mySignature = null;
	private static KeyStore myKeystore = null;
	private static KeyStore[] clientKeysArray = null;


	public ChatServer(int port)
    	{  
		try
      		{  
            		// Binds to port and starts server
			System.out.println("Binding to port " + port);
            		server_socket = new ServerSocket(port);  
            		System.out.println("Server started: " + server_socket);
            		start();
        	}
      		catch(IOException ioexception)
      		{  
            		// Error binding to port
            		System.out.println("Binding error (port=" + port + "): " + ioexception.getMessage());
        	}
    	}
    
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
    
    	public synchronized void handle(int ID, String input)
    	{  
        	if (input.equals(".quit"))
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
                		clients[i].send(ID + ": " + input);   
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
                		clientCount++; 
            		}
            		catch(IOException ioe)
            		{  
               			System.out.println("Error opening thread: " + ioe); 
            		}
       	 	}
        	else
            		System.out.println("Client refused: maximum " + clients.length + " reached.");
    	}
    
    
	public static void main(String args[]) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, InvalidKeyException, UnrecoverableEntryException {
		String input;
		ChatServer server = null;
		Scanner sc = new Scanner(System.in);

		if (args.length < 3)
			// Displays correct usage for server
			System.out.println("Usage: java ChatServer port (crtclient passclient)*");
		else {

			// Calls new server
			myKeystore = KeyStore.getInstance("JKS");

			System.out.println("Enter the password of the keystore:");
			input = sc.nextLine();
			char[] keystorePass = input.toCharArray();

			aliasPub = "serverpub";

			//load the key store from file system
			FileInputStream fileInputStream = new FileInputStream("plainserver.jks");
			myKeystore.load(fileInputStream, keystorePass);
			fileInputStream.close();

			//read the private key
			KeyStore.ProtectionParameter keyPass = new KeyStore.PasswordProtection(keystorePass);
			KeyStore.PrivateKeyEntry privKeyEntry = (KeyStore.PrivateKeyEntry) myKeystore.getEntry("plainserverkeys", keyPass);
			PrivateKey privateKey = privKeyEntry.getPrivateKey();

			//initialize the signature with signature algorithm and private key
			mySignature = Signature.getInstance("SHA256withRSA");
			mySignature.initSign(privateKey);

			clientKeysArray = new KeyStore[(int) ((args.length - 1) / 2)];
			TrustManagerFactory trustManager = null;

			for (int i = 1, j = 0; i < args.length; i += 2, ++j) {
				keystorePass = args[i + 1].toCharArray();
				clientKeysArray[j] = KeyStore.getInstance("JKS");
				clientKeysArray[j].load(new FileInputStream(args[i]), keystorePass);
				trustManager = TrustManagerFactory.getInstance("SunX509");
				trustManager.init(clientKeysArray[j]);
			}

			server = new ChatServer(Integer.parseInt(args[0]));

		}
	}

}

class ChatServerThread extends Thread
{
    private ChatServer       server    = null;
    private Socket           socket    = null;
    private int              ID        = -1;
    private DataInputStream  streamIn  =  null;
    private DataOutputStream streamOut = null;


    public ChatServerThread(ChatServer _server, Socket _socket)
    {
        super();
        server = _server;
        socket = _socket;
        ID     = socket.getPort();
    }

    // Sends message to client
    public void send(String msg)
    {
        try
        {
            streamOut.writeUTF(msg);
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
                server.handle(ID, streamIn.readUTF());
            }

            catch(IOException ioe)
            {
                System.out.println(ID + " ERROR reading: " + ioe.getMessage());
                server.remove(ID);
                stop();
            }
        }
    }


    // Opens thread
    public void open() throws IOException
    {
        streamIn = new DataInputStream(new
                        BufferedInputStream(socket.getInputStream()));
        streamOut = new DataOutputStream(new
                        BufferedOutputStream(socket.getOutputStream()));
    }

    // Closes thread
    public void close() throws IOException
    {
        if (socket != null)    socket.close();
        if (streamIn != null)  streamIn.close();
        if (streamOut != null) streamOut.close();
    }

}

