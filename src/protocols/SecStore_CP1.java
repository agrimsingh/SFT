package protocols;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Calendar;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.security.cert.CertificateException;
import javax.security.cert.X509Certificate;

public class SecStore_CP1 {
	private final static int DATA_BLOCK_SIZE = 117;
	private final static int FILE_TRANSFER_BLOCK_SIZE = 128;
	private final static int DECRYPTION_SIZE=128;
	private static DataInputStream dataInputStream;
	private static DataOutputStream dataOutputStream;
	
	/**
	 * encrypt text using private key
	 * @param nonce
	 * @param privateKey
	 * @return
	 * @throws Exception
	 */
	public static byte[] encrypt(byte[] bytes, PrivateKey privateKey) throws Exception{

		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		byte[] privateKeyBytes = privateKey.getEncoded();

	    cipher.init(Cipher.ENCRYPT_MODE, privateKey);

	    ByteArrayOutputStream baos = new ByteArrayOutputStream();

	    for(int i = 0; i < (bytes.length/DATA_BLOCK_SIZE + 1); i++)
	    {
	        int start = i * DATA_BLOCK_SIZE;
	        int blockLength;
	        if(i == bytes.length/DATA_BLOCK_SIZE)
	        {
	            blockLength = bytes.length - i * DATA_BLOCK_SIZE;
	        } else {
	            blockLength = DATA_BLOCK_SIZE;
	        }

	        if(blockLength > 0)
	        {
	            byte[] encrypted = cipher.doFinal(bytes, start, blockLength);
	            baos.write(encrypted);
	        }
	    }

	    return baos.toByteArray();
	}

	/**
	 * get private key from file
	 * @param filename
	 * @return
	 * @throws Exception
	 */
	public static PrivateKey getPrivateKey(String filename)
	throws Exception {

		File f = new File(filename);
		FileInputStream fis = new FileInputStream(f);
		DataInputStream dis = new DataInputStream(fis);
		byte[] keyBytes = new byte[(int) f.length()];
		dis.readFully(keyBytes);
		dis.close();

		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePrivate(spec);
	}

	/**
	 * 
	 * @param filename
	 * @return
	 * @throws Exception
	 */
	public static PublicKey getPublicKey(String filename)
	throws Exception {
		File f = new File(filename);
		FileInputStream fis = new FileInputStream(f);
		DataInputStream dis = new DataInputStream(fis);
		byte[] keyBytes = new byte[(int) f.length()];
		dis.readFully(keyBytes);
		dis.close();

		X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePublic(spec);
	}
	
	/**
	 * decrypt using private key
	 * @param encryptedMessage
	 * @param publicKey
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws IOException 
	 */
	public static byte[] decrypt(byte[] bytes , PrivateKey privateKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException
	{

		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		
		cipher.init(cipher.DECRYPT_MODE, privateKey);
		ByteArrayOutputStream baos = new ByteArrayOutputStream();

	    for(int i = 0; i < ((bytes.length/DECRYPTION_SIZE) +1); i++)
	    {
	        int start = i * DECRYPTION_SIZE;
	        int blockLength;
	        if(i == bytes.length/DECRYPTION_SIZE)
	        {
	            blockLength = bytes.length - i * DECRYPTION_SIZE;
	        } else {
	            blockLength = DECRYPTION_SIZE;
	        }

	        if(blockLength > 0)
	        {
	            byte[] encrypted = cipher.doFinal(bytes, start, blockLength);
	            baos.write(encrypted);
	        }
	    }
	    return baos.toByteArray();
	}


	/**
	 * reads the bytes from server
	 * @return 
	 * @throws IOException
	 */
	public static byte[] readBytes() throws IOException
	{
		try {
			int len = dataInputStream.readInt();
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			
			for(int i = 0; i < (len/FILE_TRANSFER_BLOCK_SIZE + 1); i++)
		    {
		        int start = i * FILE_TRANSFER_BLOCK_SIZE;
		        int blockLength;
		        if(i == len/FILE_TRANSFER_BLOCK_SIZE)
		        {
		            blockLength = len - i * FILE_TRANSFER_BLOCK_SIZE;
		        } else {
		            blockLength = FILE_TRANSFER_BLOCK_SIZE;
		        }
		        byte[] data = new byte[blockLength];
		        if(blockLength > 0)
		        {
		        	dataInputStream.read(data, 0, blockLength);
		        	baos.write(data);
		        }
		    }
			return baos.toByteArray();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}


	/**
	 * send byte[] to server
	 * @param byteMessage
	 * @param length
	 * @throws IOException
	 */
	public static void sendBytes(byte[] byteMessage, int length) throws IOException
	{
		if(length>0)
		{			
			dataOutputStream.writeInt(length);
			
			for(int i = 0; i < (byteMessage.length/FILE_TRANSFER_BLOCK_SIZE + 1); i++)
		    {
		        int start = i * FILE_TRANSFER_BLOCK_SIZE;
		        int blockLength;
		        if(i == byteMessage.length/FILE_TRANSFER_BLOCK_SIZE)
		        {
		            blockLength = byteMessage.length - i * FILE_TRANSFER_BLOCK_SIZE;
		        } else {
		            blockLength = FILE_TRANSFER_BLOCK_SIZE;
		        }
	
		        if(blockLength > 0)
		        {
		           dataOutputStream.write(byteMessage, start, blockLength);
		        }
		    }
		}
	}

	public static void main(String[] args) throws Exception {
		InputStream CACertStream = new FileInputStream("G:\\javaworkspace\\SFT\\cert\\CA.crt");

		X509Certificate CAcert = X509Certificate.getInstance(CACertStream);

		InputStream serverCertificateInputStream = new FileInputStream("G:\\javaworkspace\\SFT\\cert\\Ha Duc Tien ._server_1209.crt");

		X509Certificate serverCertificate = X509Certificate.getInstance(serverCertificateInputStream);

		PrivateKey server_privateKey = getPrivateKey("G:\\javaworkspace\\SFT\\cert\\privateServer.der");
		
		PublicKey server_publicKey = getPublicKey("G:\\javaworkspace\\SFT\\cert\\publicServer.der");
		
		ServerSocket serverSocket = new ServerSocket(4321);
		try {
			Socket connection = serverSocket.accept();
			String firsthandshake = "This is the server";
			
			dataInputStream = new DataInputStream(connection.getInputStream());
			dataOutputStream = new DataOutputStream(connection.getOutputStream());
	
			//waiting message
			byte[] nonce = readBytes();

			byte[] M = encrypt(nonce, server_privateKey);
			
			sendBytes(M, M.length);
			
			//receives certificate request from client
			byte[] certificateRequest = readBytes();
			
			if(Arrays.equals(certificateRequest, "certificate".getBytes()))
			{
				sendBytes(serverCertificate.getEncoded(), serverCertificate.getEncoded().length);
			}
			
			//receives file
			byte[] encryptedfile = readBytes();
			
			//decrypt file
			long startTime = System.nanoTime();
			byte[] decryptedFile = decrypt(encryptedfile, server_privateKey);
			long endTime = System.nanoTime();
			System.out.println("Time Taken to decrypt "+encryptedfile.length + " bytes "+((endTime-startTime)/1000000.0)+" ms");
		
			FileOutputStream fOutputStream = new FileOutputStream("G:\\javaworkspace\\SFT\\tests"+Calendar.getInstance().getTime().getTime());
			fOutputStream.write(decryptedFile);
			fOutputStream.close();

			dataInputStream.close();
			dataOutputStream.close();
		
		} 
		catch (Exception e) 
		{
			e.printStackTrace();
		}
	}

}