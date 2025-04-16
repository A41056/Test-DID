using System.Runtime.InteropServices;

namespace BbsSignature
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct ExternError
    {
        internal int Code;
        internal IntPtr Message;
    }
}
