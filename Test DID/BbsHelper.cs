using System.Collections.ObjectModel;

namespace Test_DID;

public static class BbsHelper
{
    public static byte[] ToByteArray(this ReadOnlyCollection<byte> collection)
    {
        if (collection == null)
        {
            throw new ArgumentNullException(nameof(collection));
        }

        byte[] result = new byte[collection.Count];
        for (int i = 0; i < collection.Count; i++)
        {
            result[i] = collection[i];
        }
        return result;
    }
}
