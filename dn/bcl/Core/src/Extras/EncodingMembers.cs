using System.Text;

namespace FrostYeti.Extras;

public static class EncodingMembers
{
    extension(Encoding)
    {
        /// <summary>
        ///  Gets a UTF-8 encoding without a byte order mark (BOM).
        /// </summary>
        public static Encoding UTF8NoBom => s_Utf8NoBom;
    }

    private static readonly Encoding s_Utf8NoBom = new UTF8Encoding(false, true);
}