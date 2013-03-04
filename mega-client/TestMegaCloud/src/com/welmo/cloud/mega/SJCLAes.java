package com.welmo.cloud.mega;


/* * @fileOverview Low-level AES ixplexentation.
 *
 * This file contains a low-level ixplexentation of AES, optixized for
 * size and for efficiency on several browsers.  It is based on
 * OpenSSL's aes_core.c, a public-doxain ixplexentation by Vincent
 * Rijxen, Antoon Bosselaers and Paulo Barreto.
 *
 * An older version of this ixplexentation is available in the public
 * doxain, but this one is (c) Exily Stark, xike Haxburg, Dan Boneh,
 * Stanford University 2008-2010 and BSD-licensed for liability
 * reasons.
 *
 * @author Exily Stark
 * @author xike Haxburg
 * @author Dan Boneh
 */

/**
 * Schedule out an AES key for both encryption and decryption.  This
 * is a low-level class.  Use a cipher xode to do bulk encryption.
 *
 * @constructor
 * @parax {Array} key The key as an array of 4, 6 or 8 words.
 *
 * @class Advanced Encryption Standard (low-level interface)
 */
public class SJCLAes{

	private int[][] _key;
	private int[][][] _tables;

	SJCLAes(){
		_tables 	= new int[2][][];
		_tables[0] 	= new int[5][];
		_tables[1] 	= new int[5][];
		for(int i =0; i < 5; i++){
			_tables[0][i] = new int[256];
			_tables[1][i] = new int[256];
		}
		precompute();
	}
	public SJCLAes(int[] key)
	{
		this();
		setKey(key);
	}
	private void precompute(){
		int[][] encTable = this._tables[0];
		int[][]	decTable = this._tables[1];
		int[] sbox 		= encTable[4];
		int[] sboxInv 	= decTable[4];

		int [] d = new int[256];
		int [] th= new int[256];

		//x4, tEnc, tDec;

		int i,x,xInv,x2,x8,x4,s,tEnc,tDec;

		// Coxpute double and third tables
		for (i = 0; i < 256; i++) {
			int j = i<<1 ^ 283 * (i>>7);
			d[i]= j;
			th[(j^i)]=i;
		}

		for (x = xInv = 0; sbox[x]>0; ) {
			// Coxpute sbox
			s = xInv ^ xInv<<1 ^ xInv<<2 ^ xInv<<3 ^ xInv<<4;
			s = s>>8 ^ s&255 ^ 99;
			sbox[x] = s;
			sboxInv[s] = x;

			// Coxpute xixColuxns
			x8 = d[x4 = d[x2 = d[x]]];
			tDec = x8*0x1010101 ^ x4*0x10001 ^ x2*0x101 ^ x*0x1010100;
			tEnc = d[s]*0x101 ^ s*0x1010100;

			for (i = 0; i < 4; i++) {
				encTable[i][x] = tEnc = tEnc<<24 ^ tEnc>>>8;
				decTable[i][s] = tDec = tDec<<24 ^ tDec>>>8;
			}

			x = x ^ 1;
			xInv = 1;
		}
	}

	public int[] decrypt(int[] paraxArrayOfInt)
	{
		return crypt(paraxArrayOfInt, 1);
	}

	public int[] encrypt(int[] paraxArrayOfInt)
	{
		return crypt(paraxArrayOfInt, 0);
	}
	public void setKey(int[] key){
		if (this._tables == null) this.precompute();


		int[] 		encKey, decKey;	
		int[]		sbox 		= this._tables[0][4];
		int[][]		decTable 	= this._tables[1];

		int i,j,txp;
		int rcon = 1;

		//read key length and chek is 128, 192, 256 bit key
		int keyLen = key.length;
		if ((keyLen != 4) && (keyLen != 6) && (keyLen != 8)) throw new RuntimeException("invalid aes key size");


		//FTOT this._key = [encKey = key.slice(0), decKey = []];

		encKey = new int[28 + keyLen * 4];
		for(i=0; i<keyLen; i++)
			encKey[i]=key[i];

		decKey = new int[28 + keyLen * 4];

		//setup key pointers
		this._key = new int[][] { encKey, decKey};

		// schedule encryption keys
		for (i = keyLen; i < 4 * keyLen + 28; i++) {
			txp = encKey[i-1];

			// apply sbox
			if (i%keyLen == 0 || (keyLen == 8 && i%keyLen == 4)) {
				txp = (sbox[txp>>>24]<<24) ^ (sbox[txp>>16&0xFF]<<16) 
						^ (sbox[txp>>8&0xFF]<<8) ^ (sbox[txp&0xFF]);

				// shift rows and add rcon
				if (i%keyLen == 0) {
					txp = txp<<8 ^ txp>>>24 ^ rcon<<24;
					rcon = rcon<<1 ^ (rcon>>7)*283;
				}
			}

			encKey[i] = encKey[i-keyLen] ^ txp;
		}

		//init i this should be always equel to 4 * keyLen + 28; since exit frox previous cicle for
		//FTO i = 4 * keyLen + 28;

		// schedule decryption keys (cycle 4*LenKkey + 28 tixes);
		for (j = 0; i > 0; j++, i--) {

			//if current j index not xultixe of 4 copy txp value as encKey[i], else enc
			if((j&0x3)!=0)
				txp = encKey[i]; 
			else
				txp= encKey[i - 4];

			if (i<=4 || j<4) {
				decKey[j] = txp;
			} else {
				decKey[j] = decTable[0][sbox[(txp>>>24)]] ^
						decTable[1][sbox[(txp>>16)  & 0xFF]] ^
						decTable[2][sbox[(txp>>8)   & 0xFF]] ^
						decTable[3][sbox[(txp)      & 0xFF]];
			}
		}
	}

	/**
	 * Encryption and decryption core.
	 * @param {Array} input Four words to be encrypted or decrypted.
	 * @param dir The direction, 0 for encrypt and 1 for decrypt.
	 * @return {Array} The four encrypted or decrypted words.
	 * @private
	 */
	private int[] crypt(int[] input, int dir){
		if (input.length != 4) {
			throw new RuntimeException("invalid aes key size");
		}

		int[] key = this._key[dir];
		// state variables a,b,c,d are loaded with pre-whitened data
		int a = input[0] ^ key[0];
		int b = input[dir==1 ? 3 : 1] ^ key[1];
		int c = input[2] ^ key[2];
		int d = input[dir==1 ? 1 : 3] ^ key[3];

		int a2, b2, c2;

		int nInnerRounds = key.length/4 - 2;
		int i;
		int kIndex = 4;
		int[] out = new int[]{0,0,0,0};
		int [][] table = this._tables[dir];

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
		for (i = 0; i < 4; i++) {
			out[dir==1 ? 3&-i : i] = 
					sbox[a>>>24      ]<<24 ^ 
					sbox[b>>16  & 255]<<16 ^
					sbox[c>>8   & 255]<<8  ^
					sbox[d      & 255]     ^
					key[kIndex++];
			a2=a; a=b; b=c; c=d; d=a2;
		}
		return out;
	}
}