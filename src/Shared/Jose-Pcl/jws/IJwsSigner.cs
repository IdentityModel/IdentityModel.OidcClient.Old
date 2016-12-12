using System.Runtime.InteropServices.WindowsRuntime;

namespace JosePCL.Jws
{
    public interface IJwsSigner
    {
        byte[] Sign([ReadOnlyArray] byte[] securedInput, object key);
        bool Verify([ReadOnlyArray] byte[] signature, [ReadOnlyArray] byte[] securedInput, object key);
        string Name { get; }
    }
}