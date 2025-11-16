namespace FrostYeti.Crypto
{
    /// <summary>
    /// The type of action for the delegate <see cref="FrostYeti.Crypto.MemoryProtectionAction"/>.
    /// </summary>
    public enum MemoryProtectionActionType
    {
        /// <summary>Encrypt data.</summary>
        Encrypt,

        /// <summary>Decrypt data.</summary>
        Decrypt,
    }
}