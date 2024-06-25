package com.konloch.tav.scanning.signature;

import com.konloch.YaraAntivirus;
import com.konloch.tav.scanning.MalwareScanner;
import com.konloch.tav.database.malware.FileSignature;
import com.konloch.tav.database.malware.MalwareScanFile;

import java.util.List;

/**
 * Handle variable length signatures through static file lookup
 *
 * @author Konloch
 * @since 6/21/2024
 */
public class VariableLengthSignatureScanner implements MalwareScanner
{
	@Override
	public String detectAsMalware(MalwareScanFile file)
	{
		List<FileSignature> fileSignatures = YaraAntivirus.AV.sqLiteDB.getByFileHash(file.getMD5Hash(),
				file.getSHA1Hash(), file.getSHA256Hash());
		
		if(fileSignatures != null)
		{
			for(FileSignature fileSignature : fileSignatures)
			{
				String hash = fileSignature.doesDetectAsMalwareType(file);
				
				if(hash != null)
					return hash;
			}
		}
		
		return null;
	}
}
