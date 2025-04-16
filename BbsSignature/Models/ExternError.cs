using System.Runtime.InteropServices;

namespace BbsSignature.Models
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct ExternError
    {
        internal int Code;
        internal IntPtr Message;
    }
}
