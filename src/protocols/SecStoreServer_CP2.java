package protocols;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Calendar;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.cert.X509Certificate;

public class SecStoreServer_CP2 {

	private static DataInputStream dataInputStream;
	private static DataOutputStream dataOutputStream;
	private final static int BLOCK_SIZE = 117;
	private final static int FILE_TRANSFER_BLOCK_SIZE = 1024;
	public static byte[] encrypt(String text, PrivateKey privateKey) throws Exception{
	    Cipher cipher = Cipher.getInstance(privateKey.getAlgorithm());
	    cipher.init(Cipher.ENCRYPT_MODE, privateKey);
	    byte[] bytes = text.getBytes("UTF-8");

	    ByteArrayOutputStream baos = new ByteArrayOutputStream();

	    for(int i = 0; i < (bytes.length/BLOCK_SIZE + 1); i++)
	    {
	        int start = i * BLOCK_SIZE;
	        int blockLength;
	        if(i == bytes.length/BLOCK_SIZE)
	        {
	            blockLength = bytes.length - i * BLOCK_SIZE;
	        } else {
	            blockLength = BLOCK_SIZE;
	        }

	        if(blockLength > 0)
	        {
	            byte[] encrypted = cipher.doFinal(bytes, start, blockLength);
	            baos.write(encrypted);
	        }
	    }

	    return baos.toByteArray();
	}

	public static byte[] encrypt(byte[] bytes, PrivateKey privateKey) throws Exception{
	    Cipher cipher = Cipher.getInstance(privateKey.getAlgorithm());
	    cipher.init(Cipher.ENCRYPT_MODE, privateKey);

	    ByteArrayOutputStream baos = new ByteArrayOutputStream();

	    for(int i = 0; i < (bytes.length/BLOCK_SIZE + 1); i++)
	    {
	        int start = i * BLOCK_SIZE;
	        int blockLength;
	        if(i == bytes.length/BLOCK_SIZE)
	        {
	            blockLength = bytes.length - i * BLOCK_SIZE;
	        } else {
	            blockLength = BLOCK_SIZE;
	        }

	        if(blockLength > 0)
	        {
	            byte[] encrypteddata = cipher.doFinal(bytes, start, blockLength);
	            baos.write(encrypteddata);
	        }
	    }

	    return baos.toByteArray();
	}

	public static PrivateKey getPrivateKey(String filelocation) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

		File file = new File(filelocation);
		FileInputStream fis = new FileInputStream(file);
		DataInputStream dis = new DataInputStream(fis);
		byte[] keyBytes = new byte[(int) file.length()];
		dis.readFully(keyBytes);
		dis.close();

		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePrivate(spec);
	}

	public static PublicKey getPublicKey(String filelocation) throws Exception {
		File file = new File(filelocation);
		FileInputStream fis = new FileInputStream(file);
		DataInputStream dis = new DataInputStream(fis);
		byte[] keyBytes = new byte[(int) file.length()];
		dis.readFully(keyBytes);
		dis.close();

		X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePublic(spec);
	}

	public static byte[] decrypt(byte[] encryptedMessage , PrivateKey privateKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
		Cipher cipher = Cipher.getInstance(privateKey.getAlgorithm());
		cipher.init(cipher.DECRYPT_MODE, privateKey);
		return cipher.doFinal(encryptedMessage);
	}

	private static SecretKey regenerateSecretKey(byte[] bytes){
		return new SecretKeySpec(bytes, 0, bytes.length, "AES");
	}
	
private static byte[] decryptWithAES(byte[] bytes, SecretKey secretKey) throws InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException,  BadPaddingException{
		Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");   
	    byte[] privateKeyBytes = secretKey.getEncoded();
	    cipher.init(Cipher.DECRYPT_MODE, secretKey);  
	    return cipher.doFinal(bytes, 0, bytes.length);
	}

	public static byte[] readBytes() throws Exception{
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

	public static void sendBytes(byte[] bytesMessage, int length) throws Exception{
		if(length>0){			
			dataOutputStream.writeInt(length);
			
			for(int i = 0; i < (bytesMessage.length/FILE_TRANSFER_BLOCK_SIZE + 1); i++){
		        int start = i * FILE_TRANSFER_BLOCK_SIZE;
		        int blockLength;
		        if(i == bytesMessage.length/FILE_TRANSFER_BLOCK_SIZE)
		        {
		            blockLength = bytesMessage.length - i * FILE_TRANSFER_BLOCK_SIZE;
		        } else {
		            blockLength = FILE_TRANSFER_BLOCK_SIZE;
		        }
	
		        if(blockLength > 0){
		           dataOutputStream.write(bytesMessage, start, blockLength);
		        }
		    }
		}
	}

	public static void main(String[] args) throws Exception {


		InputStream serverCertificateInputStream = new FileInputStream("G:\\javaworkspace\\SFT\\cert\\Ha Duc Tien ._server_1209.crt");

		X509Certificate serverCertificate = X509Certificate.getInstance(serverCertificateInputStream);

		PrivateKey server_privateKey = getPrivateKey("G:\\javaworkspace\\SFT\\cert\\privateServer.der");
		
		@SuppressWarnings("resource")
		ServerSocket serverSocket = new ServerSocket(4321);
		try {
			Socket connection = serverSocket.accept();			
			dataInputStream = new DataInputStream(connection.getInputStream());
			dataOutputStream = new DataOutputStream(connection.getOutputStream());
	
			//waiting message
			byte[] nonce = readBytes();

			byte[] M = encrypt(nonce, server_privateKey);
			
			sendBytes(M, M.length);
			
			byte[] certificateRequest = readBytes();
			
			if(Arrays.equals(certificateRequest, "certificate".getBytes()))
			{
				sendBytes(serverCertificate.getEncoded(), serverCertificate.getEncoded().length);
			}
			
			byte[] sessionKeyBytes = readBytes();
			
			byte[] decryptedSessionKey = decrypt(sessionKeyBytes, server_privateKey);
			
			SecretKey sessionKey = regenerateSecretKey(decryptedSessionKey);
			
			byte[] encryptedfile = readBytes();
			long startTime = System.nanoTime();
			byte[] decryptedFile = decryptWithAES(encryptedfile, sessionKey);
			long endTime = System.nanoTime();
			System.out.println("Time taken to decrypt "+ encryptedfile.length + " bytes: "+((endTime-startTime)/1000000.0)+" ms");
			FileOutputStream output = new FileOutputStream("G:\\javaworkspace\\SFT\\tests\\"+Calendar.getInstance().getTime().getTime()+".txt");
			output.write(decryptedFile);
			output.close();
			dataInputStream.close();
			dataOutputStream.close();
		
		} 
		catch (Exception e) 
		{
			e.printStackTrace();
		}
	}

}