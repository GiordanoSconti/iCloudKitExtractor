using iCloudKitExtractor.Models;

namespace iCloudKitExtractor.Services;

public sealed class CloudKitBootstrapException : Exception
{
    public ICloudSession Session { get; }

    public CloudKitBootstrapException(ICloudSession session, string message, Exception? inner = null)
        : base(message, inner) => Session = session;
}
