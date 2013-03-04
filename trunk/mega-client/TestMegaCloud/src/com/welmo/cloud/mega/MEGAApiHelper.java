package com.welmo.cloud.mega;

import android.util.Base64;
import android.util.SparseArray;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.IntBuffer;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.json.JSONException;
import org.json.JSONObject;

public class MEGAApiHelper
{ 
  public static int[] prepare_key(int[] keyA32)
  {
					  
    int[] pkey = { 0x93C467E3, 0x7DB0C7A4, -0xD1BE3F81, 0x0152CB56 };
    int[] key = new int[]{0, 0, 0, 0};
    int keyLen = keyA32.length;
    for(int m=0; m< 0x10000; m++){
    	for (int j=0; j < keyLen; j+=4){
    		key[0]=key[1]=key[2]=key[3]=0; 
    		 for(int i=0; i<4; i++){
    			 if((i + j) < keyLen)
    				 key[i] = keyA32[i + j];
    		 }
    		 SJCLAesII localSjclAes = new SJCLAesII();
    		 localSjclAes.setKey(key);
    		 pkey = localSjclAes.encrypt(pkey);
    	}
    }
    return pkey;
  }

  /*
  public static int[] prepare_key_pw(CharSequence paramCharSequence)
  {
    if (!prepare_key_pw_cache.containsKey(paramCharSequence))
      prepare_key_pw_cache.put(paramCharSequence, prepare_key(str_to_a32(paramCharSequence)));
    return (int[])prepare_key_pw_cache.get(paramCharSequence);
  }

*/

  public static int[] str_to_a32(CharSequence theString)
  {
	  int strLen = theString.length();
	  int[] convertedString = new int[3 + strLen >> 2];

	  for(int i=0; i < strLen; i++){
		  int k = (i >> 2);
		  convertedString[k] = (convertedString[k] | (Character.codePointAt(theString, i) << 24 - 8 * (i & 0x3)));
	  }
	  return convertedString;
  }

  /*
  public static String stringhash(CharSequence paramCharSequence, int[] paramArrayOfInt)
  {
    int[] arrayOfInt1 = str_to_a32(paramCharSequence);
    int[] arrayOfInt2 = new int[4];
    byte[] arrayOfByte1 = intToByte(paramArrayOfInt);
    int i = 0;
    Object localObject;
    Aes localAes;
    int k;
    if (i >= arrayOfInt1.length)
    {
      localObject = intToByte(arrayOfInt2);
      localAes = new Aes(arrayOfByte1);
      k = 16384;
    }
    while (true)
    {
      int m = k - 1;
      if (k == 0)
      {
        int[] arrayOfInt3 = byteToInt((byte[])localObject);
        int[] arrayOfInt4 = new int[2];
        arrayOfInt4[0] = arrayOfInt3[0];
        arrayOfInt4[1] = arrayOfInt3[2];
        return a32_to_base64(arrayOfInt4);
        int j = i & 0x3;
        arrayOfInt2[j] ^= arrayOfInt1[i];
        i++;
        break;
      }
      try
      {
        byte[] arrayOfByte2 = localAes.encrypt((byte[])localObject);
        localObject = arrayOfByte2;
        k = m;
      }
      catch (Exception localException)
      {
        log("h32 error");
        throw new RuntimeException(localException);
      }
    }
  }
  */
}