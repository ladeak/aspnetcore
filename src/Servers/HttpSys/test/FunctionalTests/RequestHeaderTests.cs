// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Buffers;
using System.Globalization;
using System.Net.Http;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpSys.Internal;
using Microsoft.AspNetCore.Testing;
using Microsoft.Extensions.Primitives;
using Microsoft.Net.Http.Headers;

namespace Microsoft.AspNetCore.Server.HttpSys;

public class RequestHeaderTests
{
    private const string CustomHeader1 = "X-Custom-1";
    private const string CustomHeader2 = "X-Custom-2";

    [ConditionalFact]
    public async Task RequestHeaders_ClientSendsDefaultHeaders_Success()
    {
        string address;
        using (Utilities.CreateHttpServer(out address, httpContext =>
            {
                var requestHeaders = httpContext.Request.Headers;
                // NOTE: The System.Net client only sends the Connection: keep-alive header on the first connection per service-point.
                // Assert.Equal(2, requestHeaders.Count);
                // Assert.Equal("Keep-Alive", requestHeaders.Get("Connection"));
                Assert.False(StringValues.IsNullOrEmpty(requestHeaders["Host"]));
                Assert.True(StringValues.IsNullOrEmpty(requestHeaders["Accept"]));
                return Task.FromResult(0);
            }))
        {
            string response = await SendRequestAsync(address);
            Assert.Equal(string.Empty, response);
        }
    }

    [ConditionalFact]
    public async Task RequestHeaders_ClientSendsCustomHeaders_Success()
    {
        using var server = Utilities.CreateHttpServer(out var address, httpContext =>
        {
            var requestHeaders = httpContext.Request.Headers;
            Assert.Equal(4, requestHeaders.Count);
            Assert.False(StringValues.IsNullOrEmpty(requestHeaders["Host"]));
            Assert.Equal("close", requestHeaders["Connection"]);
            // Apparently Http.Sys squashes request headers together.
            Assert.Single(requestHeaders["Custom-Header"]);
            Assert.Equal("custom1, and custom2, custom3", requestHeaders["Custom-Header"]);
            Assert.Single(requestHeaders["Spacer-Header"]);
            Assert.Equal("spacervalue, spacervalue", requestHeaders["Spacer-Header"]);
            return Task.FromResult(0);
        });

        var customValues = new string[] { "custom1, and custom2", "custom3" };

        var uri = new Uri(address);
        var builder = new StringBuilder();
        builder.AppendLine("GET / HTTP/1.1");
        builder.AppendLine("Connection: close");
        builder.Append("HOST: ");
        builder.AppendLine(uri.Authority);
        foreach (string value in customValues)
        {
            builder.Append("Custom-Header: ");
            builder.AppendLine(value);
            builder.AppendLine("Spacer-Header: spacervalue");
        }
        builder.AppendLine();

        var request = Encoding.ASCII.GetBytes(builder.ToString());

        using var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
        socket.Connect(uri.Host, uri.Port);
        socket.Send(request);
        var response = new byte[1024 * 5];
        var read = await Task.Run(() => socket.Receive(response));
        var result = Encoding.ASCII.GetString(response, 0, read);
        var responseStatusCode = result.Substring(9, 3); // Skip "HTTP/1.1 "
        Assert.Equal("200", responseStatusCode);
    }

    [ConditionalFact]
    public async Task RequestHeaders_ServerAddsCustomHeaders_Success()
    {
        string address;
        using (Utilities.CreateHttpServer(out address, httpContext =>
        {
            var requestHeaders = httpContext.Request.Headers;
            var header = KeyValuePair.Create("Custom-Header", new StringValues("custom"));
            requestHeaders.Add(header);

            Assert.True(requestHeaders.Contains(header));
            return Task.FromResult(0);
        }))
        {
            string response = await SendRequestAsync(address);
            Assert.Equal(string.Empty, response);
        }
    }

    [ConditionalFact]
    public async Task RequestHeaders_ClientSendTransferEncodingHeaders()
    {
        string address;
        using (Utilities.CreateHttpServer(out address, httpContext =>
        {
            var requestHeaders = httpContext.Request.Headers;
            var request = httpContext.Features.Get<RequestContext>().Request;
            Assert.Single(requestHeaders["Transfer-Encoding"]);
            Assert.Equal("chunked", requestHeaders.TransferEncoding);
            Assert.True(request.HasEntityBody);
            return Task.FromResult(0);
        }))
        {
            var headerDictionary = new HeaderDictionary(new Dictionary<string, StringValues> {
                { "Transfer-Encoding", "chunked" }
            });
            var response = await SendRequestAsync(address, headerDictionary);
            var responseStatusCode = response.Substring(9, 3); // Skip "HTTP/1.1 "
            Assert.Equal("200", responseStatusCode);
        }
    }

    [ConditionalFact]
    public async Task RequestHeaders_ClientSendTransferEncodingHeadersWithMultipleValues()
    {
        string address;
        using (Utilities.CreateHttpServer(out address, httpContext =>
        {
            var requestHeaders = httpContext.Request.Headers;
            var request = httpContext.Features.Get<RequestContext>().Request;
            Assert.Single(requestHeaders["Transfer-Encoding"]);
            Assert.Equal("gzip, chunked", requestHeaders.TransferEncoding);
            Assert.True(request.HasEntityBody);
            return Task.FromResult(0);
        }))
        {
            var headerDictionary = new HeaderDictionary(new Dictionary<string, StringValues> {
                { "Transfer-Encoding", new string[] { "gzip", "chunked" } }
            });
            var response = await SendRequestAsync(address, headerDictionary);
            var responseStatusCode = response.Substring(9, 3); // Skip "HTTP/1.1 "
            Assert.Equal("200", responseStatusCode);
        }
    }

    [ConditionalFact]
    public async Task RequestHeaders_ClientSendTransferEncodingAndContentLength_ContentLengthShouldBeRemoved()
    {
        string address;
        using (Utilities.CreateHttpServer(out address, httpContext =>
        {
            var requestHeaders = httpContext.Request.Headers;
            var request = httpContext.Features.Get<RequestContext>().Request;
            Assert.Single(requestHeaders["Transfer-Encoding"]);
            Assert.Equal("gzip, chunked", requestHeaders.TransferEncoding);

            Assert.Null(request.ContentLength);
            Assert.True(request.HasEntityBody);

            Assert.False(requestHeaders.ContainsKey("Content-Length"));
            Assert.Null(requestHeaders.ContentLength);

            Assert.Single(requestHeaders["X-Content-Length"]);
            Assert.Equal("1", requestHeaders["X-Content-Length"]);
            return Task.FromResult(0);
        }))
        {
            var headerDictionary = new HeaderDictionary(new Dictionary<string, StringValues> {
                { "Transfer-Encoding", new string[] { "gzip", "chunked" } },
                { "Content-Length", "1" },
            });
            var response = await SendRequestAsync(address, headerDictionary);
            var responseStatusCode = response.Substring(9, 3); // Skip "HTTP/1.1 "
            Assert.Equal("200", responseStatusCode);
        }
    }

    [ConditionalFact]
    public async Task RequestHeaders_AllKnownHeadersKeys_Received()
    {
        string customHeader = "X-KnownHeader";
        using var server = Utilities.CreateHttpServer(out var address, httpContext =>
        {
            var requestHeaders = httpContext.Request.Headers;
            Assert.Equal(3, requestHeaders.Count);
            Assert.Equal(requestHeaders.Keys.Count, requestHeaders.Count);
            Assert.Equal(requestHeaders.Count, requestHeaders.Values.Count);
            Assert.Contains(customHeader, requestHeaders.Keys);
            Assert.Contains(requestHeaders[customHeader].First(), requestHeaders.Keys);
            Assert.Contains(HeaderNames.Host, requestHeaders.Keys);
            return Task.FromResult(0);
        });

        foreach ((HttpSysRequestHeader Key, string Value) testRow in HeaderTestData())
        {
            var key = testRow.Key.ToString();
            var headerDictionary = new Dictionary<string, string>
            {
                { key, testRow.Value },
                { customHeader, key }
            };
            await SendRequestAsync(address, headerDictionary);
        }
    }

    [ConditionalFact]
    public async Task RequestHeaders_AllUnknownHeadersKeys_Received()
    {
        using var server = Utilities.CreateHttpServer(out var address, httpContext =>
        {
            var requestHeaders = httpContext.Request.Headers;
            Assert.Equal(4, requestHeaders.Count);
            Assert.Equal(requestHeaders.Keys.Count, requestHeaders.Count);
            Assert.Equal(requestHeaders.Count, requestHeaders.Values.Count);
            Assert.Contains("X-UnknownHeader-0", requestHeaders.Keys);
            Assert.Contains("My-UnknownHeader-1", requestHeaders.Keys);
            Assert.Contains("X-UnknownHeader-2", requestHeaders.Keys);
            Assert.Contains(HeaderNames.Host, requestHeaders.Keys);
            return Task.FromResult(0);
        });

        var headerDictionary = new Dictionary<string, string>
        {
            { "X-UnknownHeader-0", "0" },
            { "My-UnknownHeader-1", "1" },
            { "X-UnknownHeader-2", "2" }
        };
        await SendRequestAsync(address, headerDictionary);
    }

    [ConditionalFact]
    public unsafe void RequestHeaders_PooledMemory_ReturnsKnownHeadersKeys()
    {
        var nativeContext = new NativeRequestContext(MemoryPool<byte>.Shared, null, 0, false);
        var nativeMemory = new Span<byte>(nativeContext.NativeRequest, (int)nativeContext.Size + 8);

        var requestStructure = new HttpApiTypes.HTTP_REQUEST();
        SetHostAndContentTypeHeaders(nativeMemory, ref requestStructure);
        MemoryMarshal.Write(nativeMemory, ref requestStructure);

        var requestHeaders = new RequestHeaders(nativeContext);
        nativeContext.ReleasePins();

        Assert.Equal(2, requestHeaders.Count);
        Assert.Equal(requestHeaders.Count, requestHeaders.Keys.Count);
        Assert.Equal(requestHeaders.Count, requestHeaders.ToArray().Length);
        Assert.Contains(HeaderNames.Host, requestHeaders.Keys);
        Assert.Contains(HeaderNames.ContentType, requestHeaders.Keys);
    }

    [ConditionalFact]
    public unsafe void RequestHeaders_PinnedMemory_ReturnsKnownHeadersKeys()
    {
        var buffer = new byte[2048].AsMemory();
        using var handle = buffer.Pin();
        Span<byte> nativeMemory = buffer.Span;

        var requestStructure = new HttpApiTypes.HTTP_REQUEST();
        SetHostAndContentTypeHeaders(nativeMemory, ref requestStructure);
        MemoryMarshal.Write(nativeMemory, ref requestStructure);

        var nativeContext = new NativeRequestContext((HttpApiTypes.HTTP_REQUEST*)handle.Pointer, false);
        var requestHeaders = new RequestHeaders(nativeContext);

        Assert.Equal(2, requestHeaders.Count);
        Assert.Equal(requestHeaders.Count, requestHeaders.Keys.Count);
        Assert.Equal(requestHeaders.Count, requestHeaders.ToArray().Length);
        Assert.Contains(HeaderNames.Host, requestHeaders.Keys);
        Assert.Contains(HeaderNames.ContentType, requestHeaders.Keys);
    }

    [ConditionalFact]
    public unsafe void RequestHeaders_PooledMemory_ReturnsUnknownHeadersKeys()
    {
        var nativeContext = new NativeRequestContext(MemoryPool<byte>.Shared, null, 0, false);
        var nativeMemory = new Span<byte>(nativeContext.NativeRequest, (int)nativeContext.Size + 8);

        var requestStructure = new HttpApiTypes.HTTP_REQUEST();
        SetUnknownHeaders(nativeMemory, ref requestStructure, new[] { (CustomHeader1, "1"), (CustomHeader2, null) });
        MemoryMarshal.Write(nativeMemory, ref requestStructure);

        var requestHeaders = new RequestHeaders(nativeContext);
        nativeContext.ReleasePins();

        Assert.Equal(2, requestHeaders.Count);
        Assert.Equal(requestHeaders.Count, requestHeaders.Keys.Count);
        Assert.Equal(requestHeaders.Count, requestHeaders.ToArray().Length);
        Assert.Contains(CustomHeader1, requestHeaders.Keys);
        Assert.Contains(CustomHeader2, requestHeaders.Keys);
    }

    [ConditionalFact]
    public unsafe void RequestHeaders_PinnedMemory_ReturnsUnknownHeadersKeys()
    {
        var buffer = new byte[2048].AsMemory();
        using var handle = buffer.Pin();
        Span<byte> nativeMemory = buffer.Span;

        var requestStructure = new HttpApiTypes.HTTP_REQUEST();
        SetUnknownHeaders(nativeMemory, ref requestStructure, new[] { (CustomHeader1, "1"), (CustomHeader2, null) });
        MemoryMarshal.Write(nativeMemory, ref requestStructure);

        var nativeContext = new NativeRequestContext((HttpApiTypes.HTTP_REQUEST*)handle.Pointer, false);
        var requestHeaders = new RequestHeaders(nativeContext);

        Assert.Equal(2, requestHeaders.Count);
        Assert.Equal(requestHeaders.Count, requestHeaders.Keys.Count);
        Assert.Equal(requestHeaders.Count, requestHeaders.ToArray().Length);
        Assert.Contains(CustomHeader1, requestHeaders.Keys);
        Assert.Contains(CustomHeader2, requestHeaders.Keys);
    }

    [ConditionalFact]
    public unsafe void RequestHeaders_PooledMemory_DoesNotReturnInvalidKnownHeadersKeys()
    {
        var nativeContext = new NativeRequestContext(MemoryPool<byte>.Shared, null, 0, false);
        var nativeMemory = new Span<byte>(nativeContext.NativeRequest, (int)nativeContext.Size + 8);

        var requestStructure = new HttpApiTypes.HTTP_REQUEST();
        SetInvalidHostHeader(nativeMemory, ref requestStructure);
        MemoryMarshal.Write(nativeMemory, ref requestStructure);

        var requestHeaders = new RequestHeaders(nativeContext);
        nativeContext.ReleasePins();

        var result = requestHeaders.Count;
        Assert.Equal(0, result);
        Assert.Equal(requestHeaders.Count, requestHeaders.Keys.Count);
        Assert.Equal(requestHeaders.Count, requestHeaders.ToArray().Length);
    }

    [ConditionalFact]
    public unsafe void RequestHeaders_PooledMemory_DoesNotReturnInvalidUnknownHeadersKeys()
    {
        var nativeContext = new NativeRequestContext(MemoryPool<byte>.Shared, null, 0, false);
        var nativeMemory = new Span<byte>(nativeContext.NativeRequest, (int)nativeContext.Size + 8);

        var requestStructure = new HttpApiTypes.HTTP_REQUEST();
        SetInvalidUnknownHeaders(nativeMemory, ref requestStructure, new[] { CustomHeader1 });
        MemoryMarshal.Write(nativeMemory, ref requestStructure);

        var requestHeaders = new RequestHeaders(nativeContext);
        nativeContext.ReleasePins();

        var result = requestHeaders.Count;
        Assert.Equal(0, result);
        Assert.Equal(requestHeaders.Count, requestHeaders.Keys.Count);
        Assert.Equal(requestHeaders.Count, requestHeaders.ToArray().Length);
    }

    [ConditionalFact]
    public unsafe void RequestHeaders_PooledMemory_ReturnsKnownAndUnKnownHeadersKeys()
    {
        var nativeContext = new NativeRequestContext(MemoryPool<byte>.Shared, null, 0, false);
        var nativeMemory = new Span<byte>(nativeContext.NativeRequest, (int)nativeContext.Size + 8);

        var requestStructure = new HttpApiTypes.HTTP_REQUEST();
        var remainingMemory = SetUnknownHeaders(nativeMemory, ref requestStructure, new[] { (CustomHeader1, "1"), (CustomHeader2, null) });
        SetHostAndContentTypeHeaders(remainingMemory, ref requestStructure);
        MemoryMarshal.Write(nativeMemory, ref requestStructure);

        var requestHeaders = new RequestHeaders(nativeContext);
        nativeContext.ReleasePins();

        Assert.Equal(4, requestHeaders.Count);
        Assert.Equal(requestHeaders.Count, requestHeaders.Keys.Count);
        Assert.Equal(requestHeaders.Count, requestHeaders.ToArray().Length);
        Assert.Contains(HeaderNames.Host, requestHeaders.Keys);
        Assert.Contains(HeaderNames.ContentType, requestHeaders.Keys);
        Assert.Contains(CustomHeader1, requestHeaders.Keys);
        Assert.Contains(CustomHeader2, requestHeaders.Keys);
    }

    [ConditionalFact]
    public unsafe void RequestHeaders_PinnedMemory_ReturnsKnownAndUnKnownHeadersKeys()
    {
        var buffer = new byte[2048].AsMemory();
        using var handle = buffer.Pin();
        Span<byte> nativeMemory = buffer.Span;

        var requestStructure = new HttpApiTypes.HTTP_REQUEST();
        var remainingMemory = SetUnknownHeaders(nativeMemory, ref requestStructure, new[] { (CustomHeader1, "1"), (CustomHeader2, null) });
        SetHostAndContentTypeHeaders(remainingMemory, ref requestStructure);
        MemoryMarshal.Write(nativeMemory, ref requestStructure);

        var nativeContext = new NativeRequestContext((HttpApiTypes.HTTP_REQUEST*)handle.Pointer, false);
        var requestHeaders = new RequestHeaders(nativeContext);

        Assert.Equal(4, requestHeaders.Count);
        Assert.Equal(requestHeaders.Count, requestHeaders.Keys.Count);
        Assert.Equal(requestHeaders.Count, requestHeaders.ToArray().Length);
        Assert.Contains(HeaderNames.Host, requestHeaders.Keys);
        Assert.Contains(HeaderNames.ContentType, requestHeaders.Keys);
        Assert.Contains(CustomHeader1, requestHeaders.Keys);
        Assert.Contains(CustomHeader2, requestHeaders.Keys);
    }

    private async Task SendRequestAsync(string uri, IReadOnlyDictionary<string, string> headers)
    {
        HttpClient client = new HttpClient();
        foreach (var header in headers)
        {
            client.DefaultRequestHeaders.Add(header.Key, header.Value);
        }
        var result = await client.GetAsync(uri);
        result.EnsureSuccessStatusCode();
    }

    private async Task<string> SendRequestAsync(string uri)
    {
        using (HttpClient client = new HttpClient())
        {
            return await client.GetStringAsync(uri);
        }
    }

    private async Task<string> SendRequestAsync(string address, IHeaderDictionary headers)
    {
        var uri = new Uri(address);
        StringBuilder builder = new StringBuilder();
        builder.AppendLine("POST / HTTP/1.1");
        builder.AppendLine("Connection: close");
        builder.Append("HOST: ");
        builder.AppendLine(uri.Authority);
        foreach (var header in headers)
        {
            foreach (var value in header.Value)
            {
                builder.Append(header.Key);
                builder.Append(": ");
                builder.AppendLine(value);
            }
        }
        builder.AppendLine();

        byte[] request = Encoding.ASCII.GetBytes(builder.ToString());

        using (Socket socket = new Socket(SocketType.Stream, ProtocolType.Tcp))
        {
            socket.Connect(uri.Host, uri.Port);
            socket.Send(request);
            byte[] response = new byte[1024 * 5];
            var read = await Task.Run(() => socket.Receive(response));
            return Encoding.ASCII.GetString(response, 0, read);
        }
    }

    private IEnumerable<(HttpSysRequestHeader, string)> HeaderTestData()
    {
        // Allow, Expires, TE are response headers, hence excluded from this enumeration.
        // Host is sent by HttpClient, hence excluded from this enumeration.
        yield return (HttpSysRequestHeader.CacheControl, HeaderNames.CacheControl);
        yield return (HttpSysRequestHeader.Connection, HeaderNames.Connection);
        yield return (HttpSysRequestHeader.Date, new DateTime(2022, 11, 14).ToString("r", CultureInfo.InvariantCulture));
        yield return (HttpSysRequestHeader.KeepAlive, HeaderNames.KeepAlive);
        yield return (HttpSysRequestHeader.Pragma, HeaderNames.Pragma);
        yield return (HttpSysRequestHeader.Trailer, HeaderNames.Trailer);
        yield return (HttpSysRequestHeader.TransferEncoding, HeaderNames.TransferEncoding);
        yield return (HttpSysRequestHeader.Upgrade, HeaderNames.Upgrade);
        yield return (HttpSysRequestHeader.Via, "1.1 localhost");
        yield return (HttpSysRequestHeader.Warning, """199 - "just a test" """);
        yield return (HttpSysRequestHeader.ContentLength, "1");
        yield return (HttpSysRequestHeader.ContentType, "application/json");
        yield return (HttpSysRequestHeader.ContentEncoding, "utf-8");
        yield return (HttpSysRequestHeader.ContentLanguage, "en-US");
        yield return (HttpSysRequestHeader.ContentLocation, HeaderNames.ContentLocation);
        yield return (HttpSysRequestHeader.ContentMd5, HeaderNames.ContentMD5);
        yield return (HttpSysRequestHeader.ContentRange, HeaderNames.ContentRange);
        yield return (HttpSysRequestHeader.LastModified, HeaderNames.LastModified);
        yield return (HttpSysRequestHeader.Accept, "*/*");
        yield return (HttpSysRequestHeader.AcceptCharset, HeaderNames.AcceptCharset);
        yield return (HttpSysRequestHeader.AcceptEncoding, HeaderNames.AcceptEncoding);
        yield return (HttpSysRequestHeader.AcceptLanguage, HeaderNames.AcceptLanguage);
        yield return (HttpSysRequestHeader.Authorization, HeaderNames.Authorization);
        yield return (HttpSysRequestHeader.Cookie, HeaderNames.Cookie);
        yield return (HttpSysRequestHeader.Expect, HeaderNames.Expect);
        yield return (HttpSysRequestHeader.From, HeaderNames.From);
        yield return (HttpSysRequestHeader.IfMatch, HeaderNames.IfMatch);
        yield return (HttpSysRequestHeader.IfModifiedSince, HeaderNames.IfModifiedSince);
        yield return (HttpSysRequestHeader.IfNoneMatch, HeaderNames.IfNoneMatch);
        yield return (HttpSysRequestHeader.IfRange, HeaderNames.IfRange);
        yield return (HttpSysRequestHeader.IfUnmodifiedSince, HeaderNames.IfUnmodifiedSince);
        yield return (HttpSysRequestHeader.MaxForwards, HeaderNames.MaxForwards);
        yield return (HttpSysRequestHeader.ProxyAuthorization, HeaderNames.ProxyAuthorization);
        yield return (HttpSysRequestHeader.Referer, HeaderNames.Referer);
        yield return (HttpSysRequestHeader.Range, "bytes=0-4096");
        yield return (HttpSysRequestHeader.Translate, HeaderNames.Translate);
        yield return (HttpSysRequestHeader.UserAgent, HeaderNames.UserAgent);
    }

    private static unsafe Span<byte> SetHostAndContentTypeHeaders(Span<byte> nativeMemory, ref HttpApiTypes.HTTP_REQUEST requestStructure)
    {
        // Writing localhost to Host header
        var dataDestination = nativeMemory.Slice(Marshal.SizeOf<HttpApiTypes.HTTP_REQUEST>());
        int length = Encoding.ASCII.GetBytes("localhost:5001", dataDestination);
        fixed (byte* address = &MemoryMarshal.GetReference(dataDestination))
        {
            requestStructure.Headers.KnownHeaders_29.pRawValue = address;
            requestStructure.Headers.KnownHeaders_29.RawValueLength = (ushort)length;
        }

        // Writing application/json to Content-Type header
        dataDestination = dataDestination.Slice(length);
        length = Encoding.ASCII.GetBytes("application/json", dataDestination);
        fixed (byte* address = &MemoryMarshal.GetReference(dataDestination))
        {
            requestStructure.Headers.KnownHeaders_13.pRawValue = address;
            requestStructure.Headers.KnownHeaders_13.RawValueLength = (ushort)length;
        }
        dataDestination = dataDestination.Slice(length);

        return dataDestination;
    }

    private static unsafe Span<byte> SetInvalidHostHeader(Span<byte> nativeMemory, ref HttpApiTypes.HTTP_REQUEST requestStructure)
    {
        // Writing localhost to Host header
        var dataDestination = nativeMemory.Slice(Marshal.SizeOf<HttpApiTypes.HTTP_REQUEST>());
        int length = Encoding.ASCII.GetBytes("localhost:5001", dataDestination);
        fixed (byte* address = &MemoryMarshal.GetReference(dataDestination))
        {
            requestStructure.Headers.KnownHeaders_29.pRawValue = address;

            // Set length to zero, to make it invalid.
            requestStructure.Headers.KnownHeaders_29.RawValueLength = 0;
        }
        dataDestination = dataDestination.Slice(length);

        return dataDestination;
    }

    /// <summary>
    /// Writes an array HTTP_UNKNOWN_HEADER and an array of header key-value pairs to nativeMemory. Pointers in the HTTP_UNKNOWN_HEADER structure points to the corresponding key-value pair.
    /// </summary>
    private static unsafe Span<byte> SetUnknownHeaders(Span<byte> nativeMemory, ref HttpApiTypes.HTTP_REQUEST requestStructure, IReadOnlyCollection<(string Key, string Value)> headerNames)
    {
        var unknownHeaderStructureDestination = nativeMemory.Slice(Marshal.SizeOf<HttpApiTypes.HTTP_REQUEST>());
        fixed (byte* address = &MemoryMarshal.GetReference(unknownHeaderStructureDestination))
        {
            requestStructure.Headers.pUnknownHeaders = (HttpApiTypes.HTTP_UNKNOWN_HEADER*)address;
        }
        requestStructure.Headers.UnknownHeaderCount += (ushort)headerNames.Count;

        var unknownHeadersSize = Marshal.SizeOf<HttpApiTypes.HTTP_UNKNOWN_HEADER>();
        var dataDestination = unknownHeaderStructureDestination.Slice(unknownHeadersSize * headerNames.Count);
        foreach (var headerName in headerNames)
        {
            var unknownHeaderStructure = new HttpApiTypes.HTTP_UNKNOWN_HEADER();
            int nameLength = Encoding.ASCII.GetBytes(headerName.Key, dataDestination);
            fixed (byte* address = &MemoryMarshal.GetReference(dataDestination))
            {
                unknownHeaderStructure.pName = address;
                unknownHeaderStructure.NameLength = (ushort)nameLength;
            }
            dataDestination = dataDestination.Slice(nameLength);

            if (!string.IsNullOrEmpty(headerName.Value))
            {
                int valueLength = Encoding.ASCII.GetBytes(headerName.Value, dataDestination);
                fixed (byte* address = &MemoryMarshal.GetReference(dataDestination))
                {
                    unknownHeaderStructure.pRawValue = address;
                    unknownHeaderStructure.RawValueLength = (ushort)valueLength;
                }
                dataDestination = dataDestination.Slice(nameLength);
            }
            MemoryMarshal.Write(unknownHeaderStructureDestination, ref unknownHeaderStructure);
            unknownHeaderStructureDestination = unknownHeaderStructureDestination.Slice(unknownHeadersSize);
        }
        return dataDestination;
    }

    private static unsafe Span<byte> SetInvalidUnknownHeaders(Span<byte> nativeMemory, ref HttpApiTypes.HTTP_REQUEST requestStructure, IReadOnlyCollection<string> headerNames)
    {
        var unknownHeaderStructureDestination = nativeMemory.Slice(Marshal.SizeOf<HttpApiTypes.HTTP_REQUEST>());
        fixed (byte* address = &MemoryMarshal.GetReference(unknownHeaderStructureDestination))
        {
            requestStructure.Headers.pUnknownHeaders = (HttpApiTypes.HTTP_UNKNOWN_HEADER*)address;
        }

        // UnknownHeaderCount might be higher number to the headers that can be parsed out.
        requestStructure.Headers.UnknownHeaderCount += (ushort)headerNames.Count;

        var unknownHeadersSize = Marshal.SizeOf<HttpApiTypes.HTTP_UNKNOWN_HEADER>();
        var dataDestination = unknownHeaderStructureDestination.Slice(unknownHeadersSize * headerNames.Count);
        foreach (var headerName in headerNames)
        {
            var unknownHeaderStructure = new HttpApiTypes.HTTP_UNKNOWN_HEADER();
            int nameLength = Encoding.ASCII.GetBytes(headerName, dataDestination);
            fixed (byte* address = &MemoryMarshal.GetReference(dataDestination))
            {
                unknownHeaderStructure.pName = address;

                // Set the length of the name to 0 to make it invalid.
                unknownHeaderStructure.NameLength = 0;
            }
            dataDestination = dataDestination.Slice(nameLength);

            MemoryMarshal.Write(unknownHeaderStructureDestination, ref unknownHeaderStructure);
            unknownHeaderStructureDestination = unknownHeaderStructureDestination.Slice(unknownHeadersSize);
        }
        return dataDestination;
    }
}
