package com.konloch;

import com.konloch.tav.downloader.*;
import com.konloch.tav.scanning.MalwareScanners;
import com.konloch.tav.database.sqlite.SQLiteDB;
import com.konloch.tav.database.malware.DetectedSignatureFile;
import com.konloch.tav.database.malware.MalwareScanFile;

import java.io.File;
import java.util.ArrayList;

/**
 * @author Konloch
 * @since 6/21/2024
 */
public class YaraAntivirus
{
	public static YaraAntivirus AV;
	
	public static final boolean STATIC_ANALYSIS_FILE_SIGNATURE_SCANNING = false;
	public final File workingDirectory = getWorkingDirectory();
	public final SQLiteDB sqLiteDB = new SQLiteDB();
	public final MalwareScanners malwareDB = new MalwareScanners();
	public final ClamAVDownloader downloaderCDB = new ClamAVDownloader();
	public final VirusShareDownloader downloaderVS = new VirusShareDownloader();
	public final YaraHubDownloader yaraHubDownloader = new YaraHubDownloader();
	public final YaraDownloader yaraDownloader = new YaraDownloader();
	public final MalwareBazaarDownloader downloadMB = new MalwareBazaarDownloader();
	
	public void startup()
	{
		try
		{
			System.out.println("Starting up...");
			
			//load the sql db
			sqLiteDB.connect();
			sqLiteDB.createNewTable();
			
			//===================
			// VIRUS SHARE
			//===================
			
			//TODO NOTE this is too slow to actually use in production
			// instead we should gather these and distribute them as one massive download
			// this can include clamAV db and then be diffpatched for each update for minimal downloads
			
			if (STATIC_ANALYSIS_FILE_SIGNATURE_SCANNING && sqLiteDB.getLongConfig("virusshare.database.age") == 0)
			{
				System.out.println("Preforming initial VirusShare database update (This is over 450 files, please be patient)...");
				downloaderVS.downloadUpdate();
				sqLiteDB.upsertIntegerConfig("virusshare.database.age", System.currentTimeMillis());
			}
			
			//===================
			// MALWARE BAZAAR
			//===================
			
			//every week preform the malware bazaar daily update
			if(STATIC_ANALYSIS_FILE_SIGNATURE_SCANNING && System.currentTimeMillis() - sqLiteDB.getLongConfig("malwarebazaar.database.age")>= 1000 * 60 * 60 * 24 * 7)
			{
				System.out.println("Preforming weekly Malware Bazaar database update...");
				downloadMB.downloadUpdate();
				sqLiteDB.upsertIntegerConfig("malwarebazaar.database.age", System.currentTimeMillis());
			}
			
			//===================
			// CLAM ANTIVIRUS
			//===================
			
			//run initial update
			if (STATIC_ANALYSIS_FILE_SIGNATURE_SCANNING && sqLiteDB.getLongConfig("clamav.database.main.age") == 0)
			{
				System.out.println("Preforming initial ClamAV database update...");
				downloaderCDB.downloadFullUpdate();
				sqLiteDB.upsertIntegerConfig("clamav.database.main.age", System.currentTimeMillis());
				sqLiteDB.upsertIntegerConfig("clamav.database.daily.age", System.currentTimeMillis());
			}
			
			//every week preform the clamAV daily update
			if(STATIC_ANALYSIS_FILE_SIGNATURE_SCANNING && System.currentTimeMillis() - sqLiteDB.getLongConfig("clamav.database.daily.age")>= 1000 * 60 * 60 * 24 * 7)
			{
				//TODO make it every 4 hours
				// + in order to do this we need to support diffpatches and finish the libfreshclam implementation
			
				System.out.println("Preforming ClamAV daily update...");
				downloaderCDB.downloadDailyUpdate();
				sqLiteDB.upsertIntegerConfig("clamav.database.daily.age", System.currentTimeMillis());
			}
			
			//===================
			// YARA HUB
			//===================
			
			//every 4 hours download the yara hub daily update
			if(System.currentTimeMillis() - sqLiteDB.getLongConfig("yarahub.database.age")>= 1000 * 60 * 60 * 4)
			{
				System.out.println("Preforming Yara Hub daily update...");
				yaraHubDownloader.downloadUpdate();
				sqLiteDB.upsertIntegerConfig("yarahub.database.age", System.currentTimeMillis());
			}
			
			//===================
			// YARA TOOLS
			//===================
			
			//download the initial yara hub, then check in every week for an update
			if(sqLiteDB.getStringConfig("yara.tools.version").equals("") ||
					System.currentTimeMillis() - sqLiteDB.getLongConfig("yara.tools.age")>= 1000 * 60 * 60 * 24 * 7)
			{
				System.out.println("Preforming Yara Tools update...");
				boolean successful = yaraDownloader.downloadLatest();
				
				if(!successful)
				{
					//TODO handle this condition
					System.out.println("Failed to update Yara Tools...");
				}
			}
			
			//print the db stats
			sqLiteDB.printDatabaseStatistics();
		}
		catch (Exception e)
		{
			e.printStackTrace();
		}
	}
	
	public String detectAsMalware(File file)
	{
		//TODO archive support would go here, it would attempt to unzip, ungzip, tar archive etc as deep as it can go
		// then you would pass the file contents as a byte[] instead of a file, so everything is kept in memory.
		
		
		
		MalwareScanFile msf = new MalwareScanFile(file);
		return malwareDB.detectAsMalware(msf);
	}
	
	private File getWorkingDirectory()
	{
		if(workingDirectory == null)
		{
			File workingDirectory = new File(System.getProperty("user.home") + File.separator + "Yara-Antivirus");
			
			if(!workingDirectory.exists())
				workingDirectory.mkdirs();
			
			return workingDirectory;
		}
		
		return workingDirectory;
	}
	
	
	public static void main(String[] args)
	{
		if(args.length == 0)
		{
			System.out.println("Incorrect launch arguments, try passing a file or directory.");
			return;
		}
		
		AV = new YaraAntivirus();
		AV.startup();
		
		System.out.println("Preforming malware scan...");
		
		String malwareType;
		ArrayList<DetectedSignatureFile> detectedFiles = new ArrayList<>();
		for(String searchFilePath : args)
		{
			File searchFile = new File(searchFilePath);
			
			if(!searchFile.exists())
				continue;
			
			if((malwareType = AV.detectAsMalware(searchFile)) != null)
			{
				System.out.println("Detection found: " + searchFile.getAbsolutePath() + " is identified as: " + malwareType);
				detectedFiles.add(new DetectedSignatureFile(searchFile, malwareType));
			}
		}
		
		System.out.println("Malware scan completed, found " + detectedFiles.size() + " types of malware");
	}
}
