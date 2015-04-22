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
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Calendar;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.security.cert.X509Certificate;

public class SecStoreServer_CP1 {
	private static DataInputStream dataInputStream;
	private static DataOutputStream dataOutputStream;
	private final static int DATA_BLOCK_SIZE = 117;
	private final static int FILE_TRANSFER_BLOCK_SIZE = 128;
	private final static int DECRYPTION_SIZE=128;

	public static byte[] encrypt(byte[] bytes, PrivateKey privateKey) throws Exception{

		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
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

	public static PublicKey getPublicKey(String filename) throws Exception {
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
	

	public static byte[] decrypt(byte[] bytes , PrivateKey privateKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException{

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

	public static byte[] readBytes() throws IOException
	{
		try {
			int len = dataInputStream.readInt();
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			
			for(int i = 0; i < (len/FILE_TRANSFER_BLOCK_SIZE + 1); i++)
		    {
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

	public static void main(String[] args) throws Exception {

		InputStream serverCertificateInputStream = new FileInputStream("G:\\javaworkspace\\SFT\\cert\\Ha Duc Tien ._server_1209.crt");

		X509Certificate serverCertificate = X509Certificate.getInstance(serverCertificateInputStream);

		PrivateKey server_privateKey = getPrivateKey("G:\\javaworkspace\\SFT\\cert\\privateServer.der");

		

		ServerSocket serverSocket = new ServerSocket(4321);
		try {
			Socket client = serverSocket.accept();
			dataInputStream = new DataInputStream(client.getInputStream());
			dataOutputStream = new DataOutputStream(client.getOutputStream());
	

			byte[] nonce = readBytes();

			byte[] encrypt = encrypt(nonce, server_privateKey);
			
			sendBytes(encrypt, encrypt.length);

			byte[] certificateRequest = readBytes();
			
			if(Arrays.equals(certificateRequest, "certificate".getBytes()))
			{
				sendBytes(serverCertificate.getEncoded(), serverCertificate.getEncoded().length);
			}
			
			byte[] encryptedfile = readBytes();
			

			long startTime = System.nanoTime();
			byte[] decryptedFile = decrypt(encryptedfile, server_privateKey);
			long endTime = System.nanoTime();
			System.out.println("Time taken to decrypt "+encryptedfile.length + " bytes: "+((endTime-startTime)/1000000.0)+" ms");
		
			FileOutputStream output = new FileOutputStream("G:\\javaworkspace\\SFT\\tests\\"+Calendar.getInstance().getTime().getTime()+".txt");
			output.write(decryptedFile);
			output.close();

			dataInputStream.close();
			dataOutputStream.close();
			client.close();
		
		} 
		catch (Exception e) 
		{
			e.printStackTrace();
		}
	}

}