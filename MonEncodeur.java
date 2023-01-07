package secu;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;


public class MonEncodeur {

	public static String encodeCesar(String s, int k) {
		String e = "";
		for(int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			c = (char) (((c-'A'+k)%26)+'A');
			e += c;
		}
		return e;
	}
	
	public static String decodeCesar(String s, int k) {
		String e ="";
		for(int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			c = (char) (((c-'A'-k)%26)+'A');
			e += c;
		}
		return e;
	}
	
	public static String encodeVigenere(String s, String k) {
		s = s.toUpperCase();
		
		//create the longkey
		char longkey[] = new char[s.length()];
		for(int i = 0, j = 0; i < s.length(); ++i, ++j) {
			if(j == k.length()) j = 0;
			longkey[i] = k.charAt(j);
		}
		
		String e = "";
        for (int i = 0, j = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if(c == ' ') e += '=';
            else {
	            if (c < 'A' || c > 'Z') continue;
	            e += (char)((c + k.charAt(j) + 26) % 26 + 'A');
	            j = ++j % k.length();
            }
        }
        return e;
	}
	
	public static String decodeVigenere(String s, String k) {
		s = s.toUpperCase();
        
        String e = "";
        for (int i = 0, j = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if(c == '=') e += ':';
            else {
	            if (c < 'A' || c > 'Z') continue;
	            e += (char)((c - k.charAt(j) + 26) % 26 + 'A');
	            j = ++j % k.length();
            }
        }
        return e;
	}
	
	public static String encodeHill(String s, int[][] k) {
		s = s.toUpperCase();
		final int N = k.length;
		
		//prepare the string
		while(s.length() % N != 0) s += 'X';
		
		String e = "";
		
		for(int l = 0; l < s.length(); l+=N) {
			int[] P = new int[N];
			for(int j = 0; j < N; j++) {
				char c = s.charAt(j+l);
				P[j] = (int)c - 65;
			}
			
			int[] C = new int[N];
			for(int i = 0; i < N; i++) {
				for(int j = 0; j < N; j++) {
					C[i] += k[i][j] * P[j];
				}
				C[i] %= 26;
				e += (char)(C[i] + 'A');
			}
		}
		
		return e;
	}
	
	
	public static String decodeHill(String s, int[][] k) {
		
		final int N = k.length;
		
		// for matrix 2x2
		int delta = k[0][0] * k[1][1] - k[0][1] * k[1][0];
		int odal = 0;
		while(odal * delta % 26 != 1) odal++;
		
		// matrix adj
		int[][] ma = new int[N][N];
		ma[0][0] = k[1][1]; ma[1][1] = k[0][0]; ma[1][0] = k[1][0] * -1; ma[0][1] = k[0][1] * -1;
		// apply modulo 26 on adj(k)
		for(int i = 0; i < N; i++) for(int j = 0; j < N; j++) ma[i][j] = (ma[i][j] % 26 + 26) % 26;
		// multiply adj(k) mod 26 by odal
		for(int i = 0; i < N; i++) for(int j = 0; j < N; j++) ma[i][j] *= odal;
		
		// encrypt again with the new key to decrypt
		return encodeHill(s, ma);
		
	}
  
  public static String encodeAES(String s, SecretKey k) throws Exception {
	  
      Cipher codeur = Cipher.getInstance("AES");
      codeur.init(Cipher.ENCRYPT_MODE, k);
      return Base64.getEncoder().encodeToString(codeur.doFinal(s.getBytes()));
      
  }

  public static String decodeAES(String s, SecretKey k) throws Exception {
	  
      Cipher decodeur = Cipher.getInstance("AES");
      decodeur.init(Cipher.DECRYPT_MODE, k);
      return new String(decodeur.doFinal(Base64.getDecoder().decode(s)));
      
  }
  
  public static String encodeRSA(String s, PublicKey k) throws Exception {
	  
	  Cipher codeur = Cipher.getInstance("RSA");
	  codeur.init(Cipher.ENCRYPT_MODE, k);
	  return Base64.getEncoder().encodeToString(codeur.doFinal(s.getBytes()));

  }
  
  public static String decodeRSA(String s, PrivateKey k) throws Exception {
	  Cipher decodeur = Cipher.getInstance("RSA");
      decodeur.init(Cipher.DECRYPT_MODE, k);
      return new String(decodeur.doFinal(Base64.getDecoder().decode(s)));
  }

}
