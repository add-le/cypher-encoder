package secu;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class Algo {

	public static void main(String[] args) throws Exception {
		
		String s = "Bonjour tout le monde".toUpperCase();
		
		//cesar
		System.out.println("Algo Cesar :");
		System.out.println(s);
		String sc = MonEncodeur.encodeCesar(s, 3);
		System.out.println(sc);
		String sd = MonEncodeur.decodeCesar(sc, 3);
		System.out.println(sd);
		
		//vigenere
		System.out.println("\nAlgo Vigenere :");
		String v = "J adore ecouter la radio toute la journee";
		System.out.println(v);
		String vc = MonEncodeur.encodeVigenere(v, "MUSIQUE");
		System.out.println(vc);
		String vd = MonEncodeur.decodeVigenere(vc, "MUSIQUE");
		System.out.println(vd);
		
		//hill
		System.out.println("\nAlgo Hill :");
		int[][] K = {{3, 4}, {5, 9}};
		String h = "Bonjour";
		System.out.println(h);
		String hc = MonEncodeur.encodeHill(h, K);
		System.out.println(hc);
		String hd = MonEncodeur.decodeHill(hc, K);
		System.out.println(hd);
		
		/* AES */
		
		System.out.println("\nAES :");
		
		//create the key
		KeyGenerator generator = KeyGenerator.getInstance("AES");
		generator.init(128);
		SecretKey key = generator.generateKey();
		//System.out.println(key);
		
		System.out.println(s);
		
		//encode with AES
		String scAES = MonEncodeur.encodeAES(s, key) ;
		System.out.println(scAES);
		
		//decode with AES
		String sdAES = MonEncodeur.decodeAES(scAES, key) ;
		System.out.println(sdAES);
		
		/* RSA */
		
		System.out.println("\nRSA :");
		
		//create the key pair
		KeyPairGenerator pairGenerator = KeyPairGenerator.getInstance("RSA");
		pairGenerator.initialize(2048);
		KeyPair pair = pairGenerator.generateKeyPair();
		PrivateKey privateKey = pair.getPrivate();
		PublicKey publicKey = pair.getPublic();
		//System.out.println(privateKey);
		//System.out.println(publicKey);
		
		System.out.println(s);
		
		//encode with RSA
		String scRSA = MonEncodeur.encodeRSA(s, publicKey);
		System.out.println(scRSA);
		
		//decode with RSA
		String sdRSA = MonEncodeur.decodeRSA(scRSA, privateKey);
		System.out.println(sdRSA);
		
	}

}
