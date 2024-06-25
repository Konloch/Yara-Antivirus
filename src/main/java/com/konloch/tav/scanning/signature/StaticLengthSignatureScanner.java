package com.konloch.tav.scanning.signature;

import com.konloch.YaraAntivirus;
import com.konloch.tav.database.malware.FileSignature;
import com.konloch.tav.database.malware.MalwareScanFile;
import com.konloch.tav.scanning.MalwareScanner;

import java.util.List;

/**
 * .hdb: Stores MD5 or SHA1 hashes of entire malicious files
 *
 * NOTE: This database loads from two files, .hdb and .mdb
 * .mdb: Similar to .hdb, it stores MD5 hashes of malicious files.
 *
 * @author Konloch
 * @since 6/21/2024
 */
public class StaticLengthSignatureScanner implements MalwareScanner
{
	@Override
	public String detectAsMalware(MalwareScanFile file)
	{
		List<FileSignature> fileSignatures = YaraAntivirus.AV.sqLiteDB.getByFileSize(file.getSize());
		
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
