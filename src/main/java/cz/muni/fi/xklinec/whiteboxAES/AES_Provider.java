package cz.muni.fi.xklinec.whiteboxAES;

import java.security.*;

public class AES_Provider extends Provider {
	public AES_Provider() {
		super("WBAES", 1.0, "WBAES Provider (implements white-box AES)");
		
        final String BLOCK_MODES = "ECB|CBC";
        final String BLOCK_PADDINGS = "NOPADDING|ISO9797M1PADDING|ISO9797M2PADDING|PKCS5PADDING";
		
		put("Cipher.AES", "cz.muni.fi.xklinec.whiteboxAES.AES_Cipher");
        put("Cipher.AES SupportedModes", BLOCK_MODES);
        put("Cipher.AES SupportedPaddings", BLOCK_PADDINGS);
        put("Cipher.AES SupportedKeyFormats", "RAW");
		
		/*
		put("Cipher.AES/ECB/NoPadding", "cz.muni.fi.xklinec.whiteboxAES.AES_Cipher");
		put("Cipher.AES/ECB/ISO9797M1Padding", "cz.muni.fi.xklinec.whiteboxAES.AES_Cipher");
		put("Cipher.AES/ECB/ISO9797M2Padding", "cz.muni.fi.xklinec.whiteboxAES.AES_Cipher");
		put("Cipher.AES/ECB/PKCS5Padding", "cz.muni.fi.xklinec.whiteboxAES.AES_Cipher");
		*/
	}
}
