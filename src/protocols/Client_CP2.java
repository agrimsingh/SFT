package protocols;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.cert.CertificateException;
import javax.security.cert.X509Certificate;

public class Client_CP2 {
	private final static int DATA_BLOCK_SIZE = 117;
	private final static int FILE_TRANSFER_BLOCK_SIZE = 1024;

	private static DataInputStream dataInputStream;
	private static DataOutputStream dataOutputStream;

	public static byte[] decrypt(byte[] encryptedMessage , PublicKey publicKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
	{
		Cipher cipher = Cipher.getInstance(publicKey.getAlgorithm());
		cipher.init(cipher.DECRYPT_MODE, publicKey);
		return cipher.doFinal(encryptedMessage);
	}

	public static byte[] encrypt(byte[] bytes, PublicKey publicKey) throws Exception{
	    Cipher cipher = Cipher.getInstance(publicKey.getAlgorithm());
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

	private static byte[] generateNonce()
	{
		final SecureRandom random = new SecureRandom();
		byte[] bytes = new byte[16];
		random.nextBytes(bytes);
		return bytes;
	}

	private static byte[] generateAESKey() throws NoSuchAlgorithmException
	{
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(128);
		SecretKey key = keyGenerator.generateKey();
		
		return key.getEncoded();
	}

	private static SecretKey regenerateSecretKey(byte[] bytes)
	{
		return new SecretKeySpec(bytes, 0, bytes.length, "AES");
	}

	private static byte[] encryptWithAES(byte[] bytes, SecretKey secretKey) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
	{
		Cipher cipher = Cipher.getInstance(secretKey.getAlgorithm());
	    
	    byte[] privateKeyBytes = secretKey.getEncoded();

	    cipher.init(Cipher.ENCRYPT_MODE, secretKey);
	    
	    return cipher.doFinal(bytes, 0, bytes.length);
	}

	private static byte[] decryptWithAES(byte[] bytes, SecretKey secretKey) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
	{
		Cipher cipher = Cipher.getInstance(secretKey.getAlgorithm());
		
	    byte[] privateKeyBytes = secretKey.getEncoded();

	    cipher.init(Cipher.DECRYPT_MODE, secretKey);
	    
	    return cipher.doFinal(bytes, 0, bytes.length);
	}

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
			@SuppressWarnings("resource")
			Socket serverSocket = new Socket(server, port);
			
			dataInputStream = new DataInputStream(serverSocket.getInputStream());
			dataOutputStream = new DataOutputStream(serverSocket.getOutputStream());

			//generate nonce
			byte[] nonce = generateNonce();
			
			//send nonce
			sendBytes(nonce, nonce.length);
			
			//waiting for server's reply
			byte[] encryptedMessage = readBytes();
			
			//provide your certificate signed by CA
			sendBytes("certificate".getBytes(), "certificate".getBytes().length);

			//receives certificate
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
				//generate session key
				byte[] sessionKeyBytes = generateAESKey();
				
				//encrypt session key
				byte[] encryptedSessionKey = encrypt(sessionKeyBytes, serverCertificate.getPublicKey());
				
				//send encrypted session key
				sendBytes(encryptedSessionKey, encryptedSessionKey.length);
				
				SecretKey sessionKey = regenerateSecretKey(sessionKeyBytes);
				
				System.out.println("File size: "+ fileReader("G:\\javaworkspace\\SFT\\tests\\thumboo.txt").length + " bytes");
				//encrypt file with AES
				long startTime = System.nanoTime();
				byte[] encryptedFile = encryptWithAES(fileReader("G:\\javaworkspace\\SFT\\tests\\thumboo.txt"), sessionKey);
				//send file
				long endTime = System.nanoTime();
				System.out.println("Time taken to encrypt "+ encryptedFile.length + " bytes: "+((endTime-startTime)/1000000.0)+" ns");
				long startTime2 = System.nanoTime();
				sendBytes(encryptedFile, encryptedFile.length);
				long endTime2 = System.nanoTime();
				System.out.println("Time taken to transfer "+ encryptedFile.length + " bytes: "+((endTime2-startTime2)/1000000.0)+" ns");
			
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
