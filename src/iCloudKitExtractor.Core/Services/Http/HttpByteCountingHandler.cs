using System.IO;
using System.Net;
using System.Net.Http.Headers;

namespace iCloudKitExtractor.Services.Http;

/// <summary>
/// Conta i byte HTTP verso <see cref="IkeHttpTrafficMeter"/> senza bufferizzare i body.
/// <list type="bullet">
/// <item>Request/response con Content-Length: conteggio immediato (zero copia).</item>
/// <item>Response senza length: wrappa solo lo <see cref="Stream"/> di lettura
/// (CreateContentReadStreamAsync) — niente SerializeToStreamAsync che materializza tutto in RAM.</item>
/// </list>
/// </summary>
public sealed class HttpByteCountingHandler : DelegatingHandler
{
    public HttpByteCountingHandler(HttpMessageHandler innerHandler)
        : base(innerHandler)
    {
    }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        if (IkeHttpTrafficMeter.IsEnabled && request.Content is not null)
        {
            // Mai ReadAsByteArrayAsync qui: body grandi (PB) congelerebbero download/UI.
            var reqLen = request.Content.Headers.ContentLength;
            if (reqLen is > 0)
                IkeHttpTrafficMeter.AddRequest(reqLen.Value);
        }

        var response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);

        if (!IkeHttpTrafficMeter.IsEnabled || response.Content is null)
            return response;

        var respLen = response.Content.Headers.ContentLength;
        if (respLen is > 0)
        {
            IkeHttpTrafficMeter.AddResponse(respLen.Value);
            return response;
        }

        // Chunked / length assente: conta mentre l'app legge lo stream (no full-buffer).
        response.Content = new StreamCountingContent(response.Content, IkeHttpTrafficMeter.AddResponse);
        return response;
    }

    /// <summary>
    /// Delega a <see cref="CreateContentReadStreamAsync"/>; non implementa Serialize
    /// leggendo ReadAsStreamAsync sull'inner (deadlock / full buffer).
    /// </summary>
    private sealed class StreamCountingContent : HttpContent
    {
        private readonly HttpContent _inner;
        private readonly Action<long> _onBytes;
        private int _counted;

        public StreamCountingContent(HttpContent inner, Action<long> onBytes)
        {
            _inner = inner;
            _onBytes = onBytes;
            foreach (var header in inner.Headers)
                Headers.TryAddWithoutValidation(header.Key, header.Value);
        }

        protected override Task<Stream> CreateContentReadStreamAsync() =>
            CreateContentReadStreamAsync(CancellationToken.None);

        protected override async Task<Stream> CreateContentReadStreamAsync(CancellationToken cancellationToken)
        {
            var innerStream = await _inner.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            return new CountingReadStream(innerStream, ReportOnce);
        }

        protected override async Task SerializeToStreamAsync(Stream stream, TransportContext? context)
        {
            await using var source = await CreateContentReadStreamAsync().ConfigureAwait(false);
            await source.CopyToAsync(stream).ConfigureAwait(false);
        }

        protected override async Task SerializeToStreamAsync(
            Stream stream, TransportContext? context, CancellationToken cancellationToken)
        {
            await using var source = await CreateContentReadStreamAsync(cancellationToken)
                .ConfigureAwait(false);
            await source.CopyToAsync(stream, cancellationToken).ConfigureAwait(false);
        }

        protected override bool TryComputeLength(out long length)
        {
            length = 0;
            return false;
        }

        private void ReportOnce(long bytes)
        {
            if (bytes <= 0 || Interlocked.Exchange(ref _counted, 1) != 0)
                return;
            _onBytes(bytes);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
                _inner.Dispose();
            base.Dispose(disposing);
        }
    }

    private sealed class CountingReadStream : Stream
    {
        private readonly Stream _inner;
        private readonly Action<long> _onComplete;
        private long _total;
        private int _completed;

        public CountingReadStream(Stream inner, Action<long> onComplete)
        {
            _inner = inner;
            _onComplete = onComplete;
        }

        public override bool CanRead => _inner.CanRead;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => _inner.Position;
            set => throw new NotSupportedException();
        }

        public override void Flush() => _inner.Flush();

        public override int Read(byte[] buffer, int offset, int count)
        {
            var n = _inner.Read(buffer, offset, count);
            Accumulate(n);
            return n;
        }

        public override async Task<int> ReadAsync(
            byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            var n = await _inner.ReadAsync(buffer.AsMemory(offset, count), cancellationToken)
                .ConfigureAwait(false);
            Accumulate(n);
            return n;
        }

        public override async ValueTask<int> ReadAsync(
            Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            var n = await _inner.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            Accumulate(n);
            return n;
        }

        public override long Seek(long offset, SeekOrigin origin) =>
            throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                Finish();
                _inner.Dispose();
            }

            base.Dispose(disposing);
        }

        public override async ValueTask DisposeAsync()
        {
            Finish();
            await _inner.DisposeAsync().ConfigureAwait(false);
            await base.DisposeAsync().ConfigureAwait(false);
        }

        private void Accumulate(int n)
        {
            if (n > 0)
                _total += n;
            else if (n == 0)
                Finish();
        }

        private void Finish()
        {
            if (Interlocked.Exchange(ref _completed, 1) != 0)
                return;
            _onComplete(_total);
        }
    }
}
