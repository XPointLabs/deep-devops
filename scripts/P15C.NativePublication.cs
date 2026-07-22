using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

public static class P15CNativePublication
{
    private const uint GenericRead = 0x80000000;
    private const uint Delete = 0x00010000;
    private const uint FileReadAttributes = 0x00000080;
    private const uint FileListDirectory = 0x00000001;
    private const uint ShareRead = 0x00000001;
    private const uint ShareWrite = 0x00000002;
    private const uint ShareDelete = 0x00000004;
    private const uint OpenExisting = 3;
    private const uint OpenReparsePoint = 0x00200000;
    private const uint BackupSemantics = 0x02000000;
    private const uint FileAttributeDirectory = 0x00000010;
    private const uint FileAttributeReparsePoint = 0x00000400;
    private const int FileDispositionInfo = 4;
    private const int FileRenameInformation = 10;

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle file,
        out ByHandleFileInformation information);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandle(
        SafeFileHandle file,
        [Out] char[] path,
        uint pathLength,
        uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandle(
        SafeFileHandle file,
        int informationClass,
        IntPtr information,
        uint informationSize);

    [DllImport("ntdll.dll")]
    private static extern int NtSetInformationFile(
        SafeFileHandle file,
        IntPtr ioStatusBlock,
        IntPtr information,
        uint informationSize,
        int informationClass);

    [DllImport("ntdll.dll")]
    private static extern uint RtlNtStatusToDosError(int status);

    public sealed class PublicationLease : IDisposable
    {
        private SafeFileHandle file;
        private bool completed;

        internal PublicationLease(SafeFileHandle file, string finalPath)
        {
            this.file = file;
            FinalPath = finalPath;
        }

        public string FinalPath { get; private set; }

        public void Commit()
        {
            if (completed) return;
            completed = true;
            file.Dispose();
        }

        public void Rollback()
        {
            if (completed) return;
            completed = true;
            try
            {
                MarkDelete(file);
            }
            finally
            {
                file.Dispose();
            }
        }

        public void Dispose()
        {
            Commit();
        }
    }

    public static PublicationLease MoveNoReplaceVerified(
        string stagedPath,
        string destinationPath,
        string expectedSha256)
    {
        if (String.IsNullOrWhiteSpace(stagedPath) ||
            String.IsNullOrWhiteSpace(destinationPath) ||
            String.IsNullOrWhiteSpace(expectedSha256))
            throw new ArgumentException("P15C publication arguments are incomplete.");

        string expectedStage = Canonical(stagedPath);
        string expectedDestination = Canonical(destinationPath);
        string destinationParent = Path.GetDirectoryName(expectedDestination);
        string destinationLeaf = Path.GetFileName(expectedDestination);
        if (String.IsNullOrEmpty(destinationParent) || String.IsNullOrEmpty(destinationLeaf))
            throw new InvalidOperationException("P15C publication destination is invalid.");

        SafeFileHandle staged = CreateFile(
            expectedStage,
            GenericRead | Delete | FileReadAttributes,
            ShareRead | ShareWrite | ShareDelete,
            IntPtr.Zero,
            OpenExisting,
            OpenReparsePoint,
            IntPtr.Zero);
        if (staged.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            staged.Dispose();
            throw Win32("Unable to bind the P15C staged output.", error);
        }

        SafeFileHandle parent = null;
        bool renamed = false;
        try
        {
            ByHandleFileInformation sourceInformation;
            if (!GetFileInformationByHandle(staged, out sourceInformation))
                throw Win32("Unable to inspect the P15C staged output.");
            if ((sourceInformation.FileAttributes &
                 (FileAttributeDirectory | FileAttributeReparsePoint)) != 0)
                throw new InvalidOperationException("P15C staged output is not an exact regular file.");
            RequireSamePath(FinalPath(staged), expectedStage,
                "P15C staged output handle resolved to a different path.");
            RequireHash(staged, expectedSha256);

            parent = CreateFile(
                destinationParent,
                FileListDirectory | FileReadAttributes,
                ShareRead | ShareWrite | ShareDelete,
                IntPtr.Zero,
                OpenExisting,
                BackupSemantics,
                IntPtr.Zero);
            if (parent.IsInvalid)
                throw Win32("Unable to bind the P15C publication parent.");
            RequireSamePath(FinalPath(parent), destinationParent,
                "P15C publication parent changed or resolves through a reparse point.");

            RenameRelative(staged, parent, destinationLeaf);
            renamed = true;
            RequireSamePath(FinalPath(staged), expectedDestination,
                "P15C published output handle resolved to a different path.");

            parent.Dispose();
            parent = null;
            return new PublicationLease(staged, expectedDestination);
        }
        catch (Exception publicationError)
        {
            if (renamed)
            {
                try { MarkDelete(staged); }
                catch (Exception rollbackError)
                {
                    staged.Dispose();
                    if (parent != null) parent.Dispose();
                    throw new AggregateException(
                        "P15C publication verification and exact-handle rollback failed.",
                        publicationError, rollbackError);
                }
            }
            staged.Dispose();
            if (parent != null) parent.Dispose();
            throw;
        }
    }

    private static void RequireHash(SafeFileHandle file, string expected)
    {
        string actual;
#pragma warning disable 618
        using (FileStream stream = new FileStream(
            file.DangerousGetHandle(), FileAccess.Read, false, 4096, false))
#pragma warning restore 618
        using (SHA256 sha = SHA256.Create())
        {
            byte[] digest = sha.ComputeHash(stream);
            actual = BitConverter.ToString(digest).Replace("-", "").ToLowerInvariant();
            Array.Clear(digest, 0, digest.Length);
        }
        if (!String.Equals(actual, expected, StringComparison.Ordinal))
            throw new InvalidOperationException("P15C staged output changed before publication.");
    }

    private static void RenameRelative(
        SafeFileHandle file,
        SafeFileHandle parent,
        string leaf)
    {
        byte[] name = System.Text.Encoding.Unicode.GetBytes(leaf);
        int rootOffset = IntPtr.Size == 8 ? 8 : 4;
        int lengthOffset = rootOffset + IntPtr.Size;
        int nameOffset = lengthOffset + 4;
        // FILE_RENAME_INFORMATION has a trailing WCHAR[1] and native structure
        // padding beyond the FileName field offset.
        int size = checked(nameOffset + name.Length + 4);
        IntPtr buffer = Marshal.AllocHGlobal(size);
        IntPtr ioStatus = Marshal.AllocHGlobal(IntPtr.Size * 2);
        try
        {
            for (int offset = 0; offset < size; offset++) Marshal.WriteByte(buffer, offset, 0);
            for (int offset = 0; offset < IntPtr.Size * 2; offset++) Marshal.WriteByte(ioStatus, offset, 0);
            Marshal.WriteInt32(buffer, 0, 0);
            Marshal.WriteIntPtr(buffer, rootOffset, parent.DangerousGetHandle());
            Marshal.WriteInt32(buffer, lengthOffset, name.Length);
            Marshal.Copy(name, 0, IntPtr.Add(buffer, nameOffset), name.Length);
            int status = NtSetInformationFile(
                file, ioStatus, buffer, (uint)size, FileRenameInformation);
            if (status < 0)
                throw Win32("Unable to publish the P15C output without replacement.",
                    unchecked((int)RtlNtStatusToDosError(status)));
        }
        finally
        {
            Array.Clear(name, 0, name.Length);
            Marshal.FreeHGlobal(ioStatus);
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static void MarkDelete(SafeFileHandle file)
    {
        IntPtr buffer = Marshal.AllocHGlobal(4);
        try
        {
            Marshal.WriteInt32(buffer, 1);
            if (!SetFileInformationByHandle(file, FileDispositionInfo, buffer, 4))
                throw Win32("Unable to roll back the exact P15C output handle.");
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static string FinalPath(SafeFileHandle file)
    {
        char[] buffer = new char[32768];
        uint length = GetFinalPathNameByHandle(file, buffer, (uint)buffer.Length, 0);
        if (length == 0) throw Win32("Unable to resolve the final P15C handle path.");
        if (length >= buffer.Length)
            throw new InvalidOperationException("P15C final handle path is too long.");
        return Canonical(new string(buffer, 0, (int)length));
    }

    private static string Canonical(string path)
    {
        if (path.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
            path = @"\\" + path.Substring(8);
        else if (path.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase))
            path = path.Substring(4);
        string full = Path.GetFullPath(path);
        string root = Path.GetPathRoot(full);
        if (!String.Equals(full, root, StringComparison.OrdinalIgnoreCase))
            full = full.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        return full;
    }

    private static void RequireSamePath(string actual, string expected, string message)
    {
        if (!String.Equals(Canonical(actual), Canonical(expected),
            StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException(message);
    }

    private static Exception Win32(string message)
    {
        return Win32(message, Marshal.GetLastWin32Error());
    }

    private static Exception Win32(string message, int error)
    {
        return new IOException(message + " Win32 error " + error + ".",
            new Win32Exception(error));
    }
}
