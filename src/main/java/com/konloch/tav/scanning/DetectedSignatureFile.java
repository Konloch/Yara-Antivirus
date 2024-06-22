package com.konloch.tav.scanning;

import java.io.File;

/**
 * @author Konloch
 * @since 6/21/2024
 */
public class DetectedSignatureFile
{
	public final File file;
	public final String detectedMalwareType;
	
	public DetectedSignatureFile(File file, String detectedMalwareType)
	{
		this.file = file;
		this.detectedMalwareType = detectedMalwareType;
	}
}
