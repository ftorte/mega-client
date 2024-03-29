package com.welmo.cloud.mega;

public class SJCLAesII
{
  public static int PUBLIC_KEY 		= 0;
  public static int PRIVATE_KEY 	= 1;
  
  private int[][] _key;
  private int[][][] _tables;

  public SJCLAesII()
  {
    _tables = new int[2][][];
    _tables[0] = new int[5][];
    _tables[1] = new int[5][];
    
    for(int i =0; i < 5; i++){
		_tables[0][i] = new int[256];
		_tables[1][i] = new int[256];
	}
	precompute();
  }
  public SJCLAesII(int[] theKey)
  {
    this();
    setKey(theKey);
  }



  /**
   * Encryption and decryption core.
   * @param {Array} input Four words to be encrypted or decrypted.
   * @param dir The direction, 0 for encrypt and 1 for decrypt.
   * @return {Array} The four encrypted or decrypted words.
   * @private
   */
  private int[] crypt(int[] input, int dir)
  {
	  if (input.length !=4) {
		  throw new RuntimeException("invalid aes block size");
	  }

	  int[] key = this._key[dir];
	  
	  // state variables a,b,c,d are loaded with pre-whitened data
	  int a,b,c,d;
	  if(dir ==0){
		  a = input[0]^key[0];
		  b = input[1]^key[1];
		  c = input[2]^key[2];
		  d = input[3]^key[3];
	  }
	  else{
		  a = input[0]^key[0];
		  b = input[1]^key[3];
		  c = input[2]^key[2];
		  d = input[3]^key[1]; 
	  }
	  
	  int a2, b2, c2;
	 
	  int nInnerRounds = key.length/4 - 2;
	  int i;
	  int kIndex = 4;
	  int[] out = new int[]{0,0,0,0};
	  int[][] table = this._tables[dir];
	  
	  // load up the tables
      int[] t0    = table[0];
      int[] t1    = table[1];
      int[] t2    = table[2];
      int[] t3    = table[3];
      int[] sbox  = table[4];
	  
      // Inner rounds.  Cribbed from OpenSSL.
      for (i = 0; i < nInnerRounds; i++) {
    	  a2 = t0[a>>>24] ^ t1[b>>16 & 255] ^ t2[c>>8 & 255] ^ t3[d & 255] ^ key[kIndex];
    	  b2 = t0[b>>>24] ^ t1[c>>16 & 255] ^ t2[d>>8 & 255] ^ t3[a & 255] ^ key[kIndex + 1];
    	  c2 = t0[c>>>24] ^ t1[d>>16 & 255] ^ t2[a>>8 & 255] ^ t3[b & 255] ^ key[kIndex + 2];
    	  d  = t0[d>>>24] ^ t1[a>>16 & 255] ^ t2[b>>8 & 255] ^ t3[c & 255] ^ key[kIndex + 3];
    	  kIndex += 4;
    	  a=a2; b=b2; c=c2;
      }
      
      // Last round.
      if(dir==0){
    	  for (i = 0; i < 4; i++) {
    		  out[i]= (sbox[a>>>24]<<24)^(sbox[(b>>16)&255]<<16)^(sbox[(c>>8)& 255]<<8)^(sbox[d&255])^key[kIndex++];
    	      a2=a; a=b; b=c; c=d; d=a2;
    	  }
      }
      else{
    	  for (i = 0; i < 4; i++) {
    		  out[3&-i]= (sbox[a>>>24]<<24)^(sbox[(b>>16)&255]<<16)^(sbox[(c>>8)& 255]<<8)^(sbox[d&255])^key[kIndex++];
    	      a2=a; a=b; b=c; c=d; d=a2;
    	  }
      }
      return out;  
  }
  private void precompute()
  {  
    int[][] encTable = this._tables[0];
    int[][] decTable = this._tables[1];
    
    int[] sbox = encTable[4];
    int[] sboxInv = decTable[4];
    
    int i, j, x, tEnc, tDec, s, xInv, x2, x4, x8;
    
    int[] d = new int[256];
    int[] th = new int[256];
    
    // Compute double and third tables
   
    for (i = 0; i < 256; i++) {
    	j = (i<<1 ^ (i>>7)*283 )^i;
    	d[i] = j;
    	th[j]=i;
    }
    
    for (x = xInv = 0; sbox[x]!=0;) {
        // Compute sbox
        s = (xInv ^ (xInv<<1) ^ (xInv<<2) ^ (xInv<<3) ^ (xInv<<4));
        s = ((s>>8) ^ (s&255) ^ 99);
        sbox[x] = s;
        sboxInv[s] = x;
        
        // Compute MixColumns
        x8 = d[x4 = d[x2 = d[x]]];
        tDec = (x8*0x1010101) ^ (x4*0x10001) ^ (x2*0x101) ^ (x*0x1010100);
        tEnc = (d[s]*0x101) ^ (s*0x1010100);
        
        for (i = 0; i < 4; i++) {
          encTable[i][x] = (tEnc = tEnc<<24 ^ tEnc>>>8);
          decTable[i][s] = (tDec = tDec<<24 ^ tDec>>>8);
        }
        x = x ^ (x2 != 0 ? x2 : 1); 
        xInv = (th[xInv] != 0 ? th[xInv] : 1); 
      }
  }

  public int[] decrypt(int[] paramArrayOfInt)
  {
    return crypt(paramArrayOfInt, 1);
  }
  public int[] encrypt(int[] paramArrayOfInt)
  {
    return crypt(paramArrayOfInt, 0);
  }

  public void setKey(int[] theKey)
  {

	  int i, j, tmp;
	  
	  int [] sbox = this._tables[0][4]; 
	  int [][] decTable = this._tables[1];

	  int keyLen = theKey.length, rcon = 1;
	  
	  int[] encKey = new int[28 + keyLen * 4]; 
	  int[] decKey = new int[28 + keyLen * 4];

	  if ((keyLen != 4) && (keyLen != 6) && (keyLen != 8)) {
		  throw new RuntimeException("invalid aes key size");
	  }
	  
	  //init encoding Key
	  for (i=0; i < keyLen; i++)
		  encKey[i] = theKey[i];
	  
	  //Init keyvector as enkoding key & decoding key
	  this._key = new int[][] {encKey, decKey };

	  
	  // schedule encryption keys
	  for (i = keyLen; i < 4 * keyLen + 28; i++) {
		  tmp = encKey[i-1];
		  
		  // apply sbox
		  if (i%keyLen == 0 || (keyLen == 8 && i%keyLen == 4)) {
			  tmp = sbox[tmp>>>24]<<24 ^ sbox[tmp>>16&255]<<16 ^ sbox[tmp>>8&255]<<8 ^ sbox[tmp&255];

			  // shift rows and add rcon
			  if (i%keyLen == 0) {
				  tmp = tmp<<8 ^ tmp>>>24 ^ rcon<<24;
				  rcon = rcon<<1 ^ (rcon>>7)*283;
			  }
		  }
		  encKey[i] = encKey[i-keyLen] ^ tmp;
	  }
	  
	  // schedule decryption keys
	  for (j = 0; i>0; j++, i--) {
	    tmp = encKey[(j&3)!=0 ? i : i - 4];
	    if (i<=4 || j<4) {
	      decKey[j] = tmp;
	    } else {
	      decKey[j] = decTable[0][sbox[tmp>>>24      ]] ^
	                  decTable[1][sbox[tmp>>16  & 255]] ^
	                  decTable[2][sbox[tmp>>8   & 255]] ^
	                  decTable[3][sbox[tmp      & 255]];
	    }
	  }
	  
  }
}