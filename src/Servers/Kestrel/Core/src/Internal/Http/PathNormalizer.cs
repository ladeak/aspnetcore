// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Text;
using Microsoft.AspNetCore.Internal;
using Microsoft.AspNetCore.Server.Kestrel.Core.Internal.Infrastructure;

namespace Microsoft.AspNetCore.Server.Kestrel.Core.Internal.Http;

internal static class PathNormalizer
{
    private const byte ByteSlash = (byte)'/';
    private const byte ByteDot = (byte)'.';

    public static string DecodePath(Span<byte> path, bool pathEncoded, string rawTarget, int queryLength)
    {
        int pathLength;
        if (pathEncoded)
        {
            // URI was encoded, unescape and then parse as UTF-8
            pathLength = UrlDecoder.DecodeInPlace(path, isFormEncoding: false);

            // Removing dot segments must be done after unescaping. From RFC 3986:
            //
            // URI producing applications should percent-encode data octets that
            // correspond to characters in the reserved set unless these characters
            // are specifically allowed by the URI scheme to represent data in that
            // component.  If a reserved character is found in a URI component and
            // no delimiting role is known for that character, then it must be
            // interpreted as representing the data octet corresponding to that
            // character's encoding in US-ASCII.
            //
            // https://tools.ietf.org/html/rfc3986#section-2.2
            pathLength = RemoveDotSegments(path.Slice(0, pathLength));

            return Encoding.UTF8.GetString(path.Slice(0, pathLength));
        }

        pathLength = RemoveDotSegments(path);

        if (path.Length == pathLength && queryLength == 0)
        {
            // If no decoding was required, no dot segments were removed and
            // there is no query, the request path is the same as the raw target
            return rawTarget;
        }

        return path.Slice(0, pathLength).GetAsciiStringNonNullCharacters();
    }

    // In-place implementation of the algorithm from https://tools.ietf.org/html/rfc3986#section-5.2.4
    public static int RemoveDotSegments(Span<byte> src)
    {
        Debug.Assert(src[0] == '/', "Path segment must always start with a '/'");
        ReadOnlySpan<byte> slashDot = "/."u8;
        Vector<byte> vSlash = new Vector<byte>(ByteSlash);
        Vector<byte> vDot = new Vector<byte>(ByteDot);

        var writtenLength = 0;
        var readPointer = 0;

        while (src.Length > readPointer)
        {
            while (src.Length > readPointer + Vector<byte>.Count + 1)
            {
                var vInput = Vector.LoadUnsafe(ref src[readPointer]);
                var vMatchSlash = Vector.Equals(vInput, vSlash);
                var vInput1 = Vector.LoadUnsafe(ref src[readPointer + 1]);
                var vMatchDot = Vector.Equals(vInput1, vDot);
                if ((vMatchSlash & vMatchDot) == Vector<byte>.Zero)
                {
                    if (readPointer != writtenLength)
                    {
                        Vector.StoreUnsafe(vInput, ref src[writtenLength]);
                    }
                    writtenLength += Vector<byte>.Count;
                    readPointer += Vector<byte>.Count;
                }
                else
                {
                    if (Vector256.IsHardwareAccelerated)
                    {
                        uint mask = (vMatchSlash & vMatchDot).AsVector256().ExtractMostSignificantBits();
                        while (mask > 0)
                        {
                            var index = BitOperations.TrailingZeroCount(mask);
                            if (readPointer != writtenLength)
                            {
                                Unsafe.CopyBlock(ref src[writtenLength], ref src[readPointer], (uint)index);
                            }
                            writtenLength += index;
                            readPointer += index;

                            var rpBefore = readPointer;
                            if (HandleSlashDotBegin(src, ref writtenLength, ref readPointer))
                            {
                                return writtenLength;
                            }
                            mask >>= int.Min(31, index + readPointer - rpBefore);
                        }
                    }
                    break;
                }
            }

            var nextDotSegmentIndex = src[readPointer..].IndexOf(slashDot);
            if (nextDotSegmentIndex < 0 && readPointer == 0)
            {
                return src.Length;
            }
            if (nextDotSegmentIndex < 0)
            {
                // Copy the remianing src to dst, and return.
                src[readPointer..].CopyTo(src[writtenLength..]);
                writtenLength += src.Length - readPointer;
                return writtenLength;
            }
            else if (nextDotSegmentIndex > 0)
            {
                // Copy until the next segment excluding the trailer.
                Unsafe.CopyBlock(ref src[writtenLength], ref src[readPointer], (uint)nextDotSegmentIndex);
                writtenLength += nextDotSegmentIndex;
                readPointer += nextDotSegmentIndex;
            }

            if (HandleSlashDotBegin(src, ref writtenLength, ref readPointer))
            {
                return writtenLength;
            }
        }
        return writtenLength;
    }

    private static bool HandleSlashDotBegin(Span<byte> src, ref int writtenLength, ref int readPointer)
    {
        ReadOnlySpan<byte> dotSlash = "./"u8;
        ReadOnlySpan<byte> slashDot = "/."u8;

        // Case of /../ or /./
        int remainingLength = src.Length - readPointer;
        if (remainingLength > 3)
        {
            var nextIndex = readPointer + 2;
            if (src[nextIndex] == ByteSlash)
            {
                readPointer = nextIndex;
            }
            else if (MemoryMarshal.CreateSpan(ref src[nextIndex], 2).StartsWith(dotSlash))
            {
                // Remove the last segment and replace the path with /
                var lastIndex = MemoryMarshal.CreateSpan(ref src[0], writtenLength).LastIndexOf(ByteSlash);

                // Move write pointer to the end of the previous segment without / or to start position
                writtenLength = int.Max(0, lastIndex);

                // Move the read pointer to the next segments beginning including /
                readPointer += 3;
            }
            else
            {
                // No dot segment, copy the matched /. and bump the read pointer
                slashDot.CopyTo(src[writtenLength..]);
                writtenLength += 2;
                readPointer = nextIndex;
            }
            return false;
        }
        // Ending with /.. or /./
        else if (remainingLength == 3)
        {
            var nextIndex = readPointer + 2;
            if (src[nextIndex] == ByteSlash)
            {
                // Replace the /./ segment with a closing /
                src[writtenLength++] = ByteSlash;
                return true;
            }
            else if (src[nextIndex] == ByteDot)
            {
                // Remove the last segment and replace the path with /
                var lastSlashIndex = MemoryMarshal.CreateSpan(ref src[0], writtenLength).LastIndexOf(ByteSlash);

                // If this was the beginning of the string, then return /
                if (lastSlashIndex < 0)
                {
                    src[0] = ByteSlash;
                    writtenLength = 1;
                    return true;
                }
                else
                {
                    writtenLength = lastSlashIndex + 1;
                }
                return true;
            }
            else
            {
                // No dot segment, copy the /. and bump the read pointer.
                slashDot.CopyTo(src[writtenLength..]);
                writtenLength += 2;
                readPointer = nextIndex;
            }
        }
        // Ending with /.
        else if (remainingLength == 2)
        {
            src[writtenLength++] = ByteSlash;
            return true;
        }
        return false;
    }

    public static bool ContainsDotSegments(Span<byte> src)
    {
        Debug.Assert(src[0] == '/', "Path segment must always start with a '/'");
        ReadOnlySpan<byte> slashDot = "/."u8;
        ReadOnlySpan<byte> dotSlash = "./"u8;
        while (src.Length > 0)
        {
            var nextSlashDotIndex = src.IndexOf(slashDot);
            if (nextSlashDotIndex < 0)
            {
                return false;
            }
            else
            {
                src = src[(nextSlashDotIndex + 2)..];
            }
            switch (src.Length)
            {
                case 0: // Case of /.
                    return true;
                case 1: // Case of /.. or /./
                    if (src[0] == ByteDot || src[0] == ByteSlash)
                    {
                        return true;
                    }
                    break;
                default: // Case of /../ or /./ 
                    if (dotSlash.SequenceEqual(src[..2]) || src[0] == ByteSlash)
                    {
                        return true;
                    }
                    break;
            }
        }
        return false;
    }
}
