package main;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.security.spec.KeySpec;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class Lab01 {

	static String pathResultFile = "D:\\eclipse-workspace\\Lab01_InfSec1\\test.csv";
	//static String pathProject = "D:\\eclipse-workspace\\Lab01_InfSec1\\";
	static String sink = "";//"D:\\eclipse-workspace\\Lab01_InfSec1\\";
	
	public static void main (String[] args)throws Exception	{	

		if (args.length != 6) uso();
		String algo = args[0];
		int levelSecurity = Integer.parseInt(args[1]);
		String source = args[4];
		sink = args[5];
		
		System.out.println("\nCleaning directories to save files ... ");
		Utilities.deleteFiles(sink+algo+"\\enc\\");
		Utilities.deleteFiles(sink+algo+"\\dec\\");
		
		System.out.println("Reading files to encrypt from ... "+source);
		if ("-c".equals(args[2])) {
			File[]  target =  Utilities.readFiles(source);
			char[] password = args[3].toCharArray();

			final byte[] salt = new byte[64];
			SecureRandom random = SecureRandom.getInstanceStrong();
			random.nextBytes(salt);

			long sizeFiles = 0; for(File file : target) {sizeFiles = sizeFiles + file.length();}

			System.out.println("Generating key");
			String instance = "";
			int sizeKey = 0;
			if(checkSpecification(levelSecurity, algo)) {
				instance = getInstanceAlgo(levelSecurity,algo);
				sizeKey = levelSecurity;

				SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(instance);
				KeySpec passwordBasedEncryptionKeySpec = new PBEKeySpec(password, salt, 10000,sizeKey);
				SecretKey secretKeyFromPBKDF2 = secretKeyFactory.generateSecret(passwordBasedEncryptionKeySpec);
				SecretKey key = new SecretKeySpec(secretKeyFromPBKDF2.getEncoded(), algo);


				System.out.println("Encrypting using "+algo);

				if(algo.equals("3DES")) {
					KeySpec pbeSpec = new PBEKeySpec(password, salt, 1000,192);
					key = SecretKeyFactory.getInstance(instance).generateSecret(pbeSpec);
				}
				long start = System.currentTimeMillis();
				for(File file : target) {
					byte[] fileData = Files.readAllBytes(Paths.get(file.getPath()));
					processCipher(algo,key,fileData,file.getName());								
				}
				long totalTime = (System.currentTimeMillis() - start);
				Utilities.writeTimeResults(algo+",encrypt,"+String.valueOf(sizeKey)+","+String.valueOf(sizeFiles)+","+totalTime, pathResultFile);	

				//############################################################################################################################
				// Steps to decrypt files
				//############################################################################################################################
				System.out.println("Reading files to decrypt from ... "+sink+algo+"\\enc\\");
				System.out.println("Decrypting using "+algo);
				File[]  targetDec = Utilities.readFiles(sink+algo+"\\enc\\");
				sizeFiles = 0;
				for(File file : targetDec) {sizeFiles = sizeFiles + file.length();}

				start = System.currentTimeMillis();
				for(File file : targetDec) {
					byte[] fileData = Files.readAllBytes(Paths.get(file.getPath()));
					processDeCipher(algo,key,fileData,file.getName());
				}
				totalTime = (System.currentTimeMillis() - start);
				Utilities.writeTimeResults(algo+",decrypt,"+String.valueOf(sizeKey)+","+String.valueOf(sizeFiles)+","+totalTime, pathResultFile);	

				if(ckeckIntegrity(source, sink+algo+"\\dec\\")){
					System.out.println("\nSuccessful process: All files have the same content!!!");
				}else {
					System.out.println("\nError: files have not the same content!!!");
				}


			}else {
				System.err.println(algo+" does not accept "+levelSecurity+" for level security");
			}
		}

		//##############################################################//##############################################################
		//
		//THIS IMPLEMENTATION IS IN PROGRESS, TO ACCEPT SEPARATE STEPS (Encrypt or Decrypt process)
		//
		//##############################################################//##############################################################

		else if ("-e".equals(args[2])) { 
			System.out.print("Coding in progress....THIS IMPLEMENTATION IS IN PROGRESS....");
		}else if ("-d".equals(args[2])) { 
			System.out.print("Coding in progress....THIS IMPLEMENTATION IS IN PROGRESS....");
		}           
		else uso();
	}


	private static boolean ckeckIntegrity(String pathInitial, String pathFinal) {
		String shaAlgo = "SHA3-256";
		if(ShaScript.checkIntegrity(pathInitial, pathFinal, shaAlgo)) {
			return true;
		}
		return false;
	}


	private static void processCipher(String algo, SecretKey key, byte[] fileData,String fileName) {
		Cipher cipherE1 = null;
		if(algo.equals("DES")) {
			cipherE1  = new MyDES();
			byte[] myKey = key.getEncoded();
			byte[] myCipherText = cipherE1.encrypt(fileData, myKey);			
			Utilities.writeOnDisk(sink+algo+"\\enc\\"+fileName+"."+algo.toLowerCase(),myCipherText);	
		}else if(algo.equals("3DES")) {
			cipherE1  = new My3DES();
			byte[] myKey = key.getEncoded();
			byte[] myCipherText = cipherE1.encrypt(fileData, myKey);
			Utilities.writeOnDisk(sink+algo+"\\enc\\"+fileName+"."+algo.toLowerCase(),myCipherText);
		}else if(algo.equals("AES")) {
			cipherE1  = new MyAES();
			byte[] myKey = key.getEncoded();
			byte[] myCipherText = cipherE1.encrypt(fileData, myKey);			
			Utilities.writeOnDisk(sink+algo+"\\enc\\"+fileName+"."+algo.toLowerCase(),myCipherText);
		}		
	}


	private static void processDeCipher(String algo, SecretKey key, byte[] fileData, String fileName) {
		Cipher cipherE1 = null;
		if(algo.equals("DES")) {
			cipherE1  = new MyDES();
			byte[] myKey = key.getEncoded();
			byte[] myPlainText = cipherE1.decrypt(fileData, myKey);			
			Utilities.writeOnDisk(sink+algo+"\\dec\\"+fileName.substring(0, fileName.lastIndexOf('.')),myPlainText);
		}else if(algo.equals("3DES")) {
			cipherE1  = new My3DES();
			byte[] myKey = key.getEncoded();
			byte[] myPlainText = cipherE1.decrypt(fileData, myKey);
			Utilities.writeOnDisk(sink+algo+"\\dec\\"+fileName.substring(0, fileName.lastIndexOf('.')),myPlainText);
		}else if(algo.equals("AES")) {
			cipherE1  = new MyAES();
			byte[] myKey = key.getEncoded();
			byte[] myPlainText = cipherE1.decrypt(fileData, myKey);			
			Utilities.writeOnDisk(sink+algo+"\\dec\\"+fileName.substring(0, fileName.lastIndexOf('.')),myPlainText);
		}	
	}


	private static String getInstanceAlgo(int levelS, String algo) {
		String result = "";
		if(levelS==64 && algo.equals("DES")){
			result = "PBEWithMD5AndDES";
		}else if(levelS==168 && algo.equals("3DES")){
			result = "PBKDF2WithHmacSHA384";
		}else if(levelS==128 && algo.equals("AES")){
			result = "PBKDF2WithHmacSHA256";
		}else if(levelS==192 && algo.equals("AES")){
			result = "PBKDF2WithHmacSHA384";
		}else if(levelS==256 && algo.equals("AES")){
			result = "PBKDF2WithHmacSHA512";
		}
		return result;
	}


	private static boolean checkSpecification(int levelS, String algo) {
		boolean result = false;
		if(levelS==64 && algo.equals("DES")){
			result = true;
		}else if(levelS==168 && algo.equals("3DES")){
			result = true;
		}else if((levelS==128||levelS==192||levelS==256) && algo.equals("AES")){
			result = true;
		} 	    
		return result;
	}


	private static void uso(){
		System.err.println("Uso: java main/Lab01 typeEncrypt[DES|3DES|AES] levelSecurity[64|128|168|192|256] [-c|-e|-d] password sourcePath sinkPath");
		System.exit(1);
	}

	
}
