using System.Runtime.InteropServices;

namespace Test_DID;

[StructLayout(LayoutKind.Sequential)]
internal struct ExternError
{
    internal int Code;
    internal IntPtr Message;
}
