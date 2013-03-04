package com.welmo.cloud.mega;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.Socket;
import java.net.URLEncoder;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.IntBuffer;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.entity.StringEntity;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import com.loopj.android.http.AsyncHttpClient;
import com.loopj.android.http.AsyncHttpResponseHandler;
import com.loopj.android.http.JsonHttpResponseHandler;
import com.loopj.android.http.RequestParams;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.os.AsyncTask;
import android.os.Bundle;
import android.os.Message;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.TextView;

public class LoginActivity extends Activity {

	// ****************************************************************************************
	//  Inner Classes
	// ****************************************************************************************
	public class ButtonListner implements OnClickListener{
		@Override
		public void onClick(View arg0) {
			password = ((TextView)findViewById(R.id.editPassword)).getText().toString();
			username = ((TextView)findViewById(R.id.editUsername)).getText().toString();
			doLogin();
		}
	}; 
	
	// ****************************************************************************************
	//  variables
	// ****************************************************************************************
	Context					ctx;
	String 					password="";
	String 					username="";
	String					cloudServer = "https://eu.api.mega.co.nz/cs?";
	
	String	 				response;
	Integer 				errorcode;
	static final String  	TAG 		= "TestMacaCloudActivity";
	

	/** Called when the activity is first created. */
	@Override
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.login);

		ctx = this;

		// setup default value (to change)
		// TODO change function and create function that read configuration value
		((TextView)findViewById(R.id.editPassword)).setText("TFTsw92grse0605");
		((TextView)findViewById(R.id.editUsername)).setText("torterolo@orange.fr");
							
				
		//create buttons event handler
		Button loginButton = (Button)findViewById(R.id.btnLogin);
		loginButton.setOnClickListener(new ButtonListner());

	} 

	public void doLogin(){
	
		StringEntity se=null;
		
		int[] password_a32 	= MEGAApiHelper.str_to_a32(password);
		int[] key 			= MEGAApiHelper.prepare_key(password_a32);
		

		try {
			//se = new StringEntity(loginInfo.toString());
			se = new StringEntity("[{\"a\": \"us\", \"user\": \"torterolo@orange.fr\", \"uh\": \"MJ3JrQdJV0E\"}]");

		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		AsyncHttpClient client = new AsyncHttpClient();

		
		String 	URL 	= "https://eu.api.mega.co.nz/cs?";
		//https://g.api.mega.co.nz/cs?id=922159119
		//String 		URL 	= "https://posttestserver.com/post.php/cs?id=922159110";
			
		String theURL="";
		try {
			theURL = (new StringBuilder(String.valueOf(URL))).append("id=").append(URLEncoder.encode(
					(new StringBuilder(String.valueOf(922159119))).toString(), "UTF-8")).append("&").toString();
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
       

		client.post(this.getApplicationContext(),theURL,se, "application/x-www-form-urlencoded",new AsyncHttpResponseHandler() {
			private void process(String s, Throwable throwable){
				
			}
			@Override
			public void onFailure(Throwable throwable, String s)
            {
				errorcode = Integer.valueOf(s).intValue();
            }
			@Override
			public void onSuccess(String s)
			{
				//MegaResponse megaresponse = MegaResponse.fromJson(s)
				
				AlertDialog alertDialog;
				alertDialog = new AlertDialog.Builder(ctx).create();
				alertDialog.setTitle("Key response");
				alertDialog.setMessage(s);
				alertDialog.show();
				
				try{
					JSONArray localJSONArray = new JSONArray(s);
					try {
						JSONObject responseObject = localJSONArray.getJSONObject(0);
						if (responseObject.has("e"))
							Log.i(TAG,"ERROR");
						return;
					}
				    catch (JSONException localJSONException1){
				        String str = localJSONArray.getString(0);
				        /* try {
				          localMegaError = MegaError.getErrorByCode(Integer.valueOf(str).intValue());
				          if (localMegaError == MegaError.UNKNOWN_ERROR)
				          {
				            localMegaResponse.responseString = str;
				            return localMegaResponse;
				          }
				        }
				        catch (NumberFormatException localNumberFormatException)
				        {
				          localMegaResponse.responseString = str;
				          return localMegaResponse;
				        }*/
				        return;
				      }
				    }
				    catch (NullPointerException localNullPointerException){
				    	// MegaError localMegaError;
				    	// localMegaResponse.error = MegaError.RESPONSE_ENCODING_ERROR;
				    	// return localMegaResponse;
				    	// localMegaResponse.error = localMegaError;
				    	// return localMegaResponse;
				    	return;
				    }
				    catch (JSONException localJSONException2)
				    {
				      //localMegaResponse.error = MegaError.RESPONSE_ENCODING_ERROR;
				      return;	
				    }
				    //return localMegaResponse;
            }
		});
	}		
}