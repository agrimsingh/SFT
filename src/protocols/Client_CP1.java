package protocols;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.Writer;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.print.attribute.standard.MediaSize.NA;
import javax.security.cert.CertificateException;
import javax.security.cert.X509Certificate;

public class Client_CP1 {
	private final static int DATA_BLOCK_SIZE = 117;
	private final static int FILE_TRANSFER_BLOCK_SIZE = 128;
	
	private static DataInputStream dataInputStream;
	private static DataOutputStream dataOutputStream;
	
	/**
	 * Client file data encryption using server's public key
	 * @param file data
	 * @param server's publicKey
	 * @return
	 * @throws Exception
	 */
	public static byte[] encrypt(byte[] bytes, PublicKey publicKey) throws Exception{
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
	    
	    byte[] privateKeyBytes = publicKey.getEncoded();

	    cipher.init(Cipher.ENCRYPT_MODE, publicKey);

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
	 * Decryption using the public key
	 * @param encryptedMessage
	 * @param publicKey
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public static byte[] decrypt(byte[] encryptedMessage , PublicKey publicKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
	{
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(cipher.DECRYPT_MODE, publicKey);
		return cipher.doFinal(encryptedMessage);
	}
	
	/**
	 * reads a file and returns byte array
	 * @param filename
	 * @return file byte array
	 */
	public static byte[] fileReader(String filename)
	{
		byte[] fileData = null;
		try {

			File file = new File(filename);
			
			fileData = new byte[(int)file.length()];
			
			FileInputStream fileInputStream = new FileInputStream(file);
			fileInputStream.read(fileData);
			fileInputStream.close();		
	   
		} catch (Exception e) {
			e.printStackTrace();
		}
		return fileData;
	}
	
	/**
	 * Generates a nonce and returns the byte array
	 * @return
	 */
	private static byte[] generateNonce()
	{
		final SecureRandom random = new SecureRandom();
		byte[] bytes = new byte[16];
		random.nextBytes(bytes);
		return bytes;
	}

	/**
	 * Reads the bytes from the server
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
	
	public static void main(String[] args) throws FileNotFoundException, CertificateException {
		
		String server = "localhost";
		int port = 4321;
		
		InputStream CACertStream = new FileInputStream("G:\\javaworkspace\\SFT\\cert\\CA.crt");

		X509Certificate CAcert = X509Certificate.getInstance(CACertStream);
		
		try {
			Socket serverSocket = new Socket(server, port);
			
			dataInputStream = new DataInputStream(serverSocket.getInputStream());
			dataOutputStream = new DataOutputStream(serverSocket.getOutputStream());
				
			
//			client sends identity request
//			sendBytes("request identity".getBytes(), "request identity".getBytes().length);
			
			//generate nonce
			byte[] nonce = generateNonce();
			
			//send nonce
			sendBytes(nonce, nonce.length);
			
			//waiting for server's reply
			byte[] encryptedMessage = readBytes();
			
			//provide the certificate signed by CA
			sendBytes("certificate".getBytes(), "certificate".getBytes().length);

			//receive certificate
			byte[] certificate = readBytes();
			
			X509Certificate serverCertificate = X509Certificate.getInstance(certificate);
			try 
			{
				serverCertificate.checkValidity();
				serverCertificate.verify(CAcert.getPublicKey());
			} catch (Exception e) {
				e.printStackTrace();
			}
			//decrypt message 
			byte[] decryptedMessage = decrypt(encryptedMessage, serverCertificate.getPublicKey());			
			
			if(Arrays.equals(decryptedMessage, nonce))
			{
				System.out.println("file size "+ fileReader("G:\\javaworkspace\\SFT\\tests\\adam.txt").length);
				//encrypt file
				byte[] encryptedFile = encrypt(fileReader("G:\\javaworkspace\\SFT\\tests\\adam.txt"), serverCertificate.getPublicKey());
				
				//send encrypted file
				long startTime = System.nanoTime();
				sendBytes(encryptedFile, encryptedFile.length);
				long endTime = System.nanoTime();
				System.out.println("Time Taken to Transfer "+ encryptedFile.length + " bytes: "+((endTime-startTime)/1000000.0)+" ms");
				
				dataInputStream.close();
				dataOutputStream.close();
			}
			else {
				dataInputStream.close();
				dataOutputStream.close();
			}
		}
		catch(Exception e)
		{
			e.printStackTrace();
		}
	}
	
}
