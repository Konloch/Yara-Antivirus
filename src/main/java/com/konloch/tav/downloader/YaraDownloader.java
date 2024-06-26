package com.konloch.tav.downloader;

import com.konloch.YaraAntivirus;
import com.konloch.httprequest.HTTPRequest;
import com.konloch.util.FastStringUtils;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * @author Konloch
 * @since 6/25/2024
 */
public class YaraDownloader
{
	public boolean downloadLatest() throws IOException, SQLException
	{
		boolean isWindows = System.getProperty("os.name").toLowerCase().contains("win");
		String architecture = System.getProperty("os.arch");
		String arch;
		
		if(!isWindows)
			throw new RuntimeException("This is currently windows only - YaraX might be a solution, open a ticket and let us know you need it.");
		
		if (architecture.equals("x86") || architecture.equals("i386") || architecture.equals("i686"))
			arch = "32";
		else if (architecture.equals("amd64") || architecture.equals("x86_64"))
			arch = "64";
		else
			throw new RuntimeException("Only 32bit & 64bit are supported, cannot support: " + architecture);
		
		HTTPRequest request = new HTTPRequest("https://github.com/VirusTotal/yara/releases/latest");
		ArrayList<String> lines = request.read();
		for(String line : lines)
		{
			if(line.contains("href=\"/VirusTotal/yara/releases/tag/"))
			{
				int startIndex = line.indexOf("href=\"") + 6;
				int endIndex = line.indexOf("\"", startIndex);
				String url = "https://github.com" + line.substring(startIndex, endIndex);
				String version = FastStringUtils.split(url, "/")[6];
				String downloadURL = "https://github.com/VirusTotal/yara/releases/expanded_assets/" + version;
				
				if(version.isEmpty()) //failed to fetch correctly
					return false;
				
				//check version, if already downloaded just exit early
				if(YaraAntivirus.AV.sqLiteDB.getStringConfig("yara.tools.version").equals(version))
				{
					YaraAntivirus.AV.sqLiteDB.upsertIntegerConfig("yara.tools.age", System.currentTimeMillis());
					return true;
				}
				
				request = new HTTPRequest(downloadURL);
				lines = request.read();
				
				for(String line2 : lines)
				{
					if(line2.contains("<a href=\"") && line2.contains("win" + arch + ".zip"))
					{
						startIndex = line2.indexOf("href=\"") + 6;
						endIndex = line2.indexOf("\"", startIndex);
						url = "https://github.com" + line2.substring(startIndex, endIndex);
						downloadFile(url, "yara.zip");
						extract("yara.zip");
						YaraAntivirus.AV.sqLiteDB.upsertStringConfig("yara.tools.version", version);
						YaraAntivirus.AV.sqLiteDB.upsertIntegerConfig("yara.tools.age", System.currentTimeMillis());
						return true;
					}
				}
				
				break;
			}
		}
		
		return false;
	}
	
	private void downloadFile(String url, String fileName) throws IOException
	{
		File updateFile = new File(YaraAntivirus.AV.workingDirectory, fileName);
		HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
		connection.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:25.0) Gecko/20100101 Firefox/25.0");
		
		System.out.println("Downloading " + url + " to " + updateFile.getAbsolutePath());
		
		try (InputStream inputStream = connection.getInputStream();
		     FileOutputStream fileOutputStream = new FileOutputStream(updateFile))
		{
			byte[] buffer = new byte[4096];
			int bytesRead;
			
			while ((bytesRead = inputStream.read(buffer)) != -1)
			{
				fileOutputStream.write(buffer, 0, bytesRead);
			}
		}
		finally
		{
			connection.disconnect();
		}
	}
	
	private void extract(String databaseZipPath) throws FileNotFoundException
	{
		File databaseZip = new File(YaraAntivirus.AV.workingDirectory, databaseZipPath);
		File updateFile = YaraAntivirus.AV.workingDirectory;
		
		if(!databaseZip.exists())
			throw new FileNotFoundException("Yara Update File Not Found: " + updateFile.getAbsolutePath());
		
		extractDatabase(databaseZip, updateFile);
		
		System.out.println("Deleting " + databaseZip.getAbsolutePath());
		databaseZip.delete();
	}
	
	public static void extractDatabase(File zipFile, File outputFolder)
	{
		try (FileInputStream fis = new FileInputStream(zipFile);
		     ZipInputStream zis = new ZipInputStream(fis))
		{
			ZipEntry entry;
			while ((entry = zis.getNextEntry()) != null)
			{
				File outputFile = new File(outputFolder, entry.getName());
				
				//zipslip
				if(!outputFile.getAbsolutePath().startsWith(outputFolder.getAbsolutePath()))
					continue;
				
				if (entry.isDirectory())
					outputFile.mkdirs();
				else
				{
					outputFile.getParentFile().mkdirs();
					try (BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(outputFile)))
					{
						byte[] buffer = new byte[1024];
						int len;
						while ((len = zis.read(buffer)) > 0)
						{
							bos.write(buffer, 0, len);
						}
					}
				}
			}
		}
		catch (IOException e)
		{
			e.printStackTrace();
		}
	}
}
