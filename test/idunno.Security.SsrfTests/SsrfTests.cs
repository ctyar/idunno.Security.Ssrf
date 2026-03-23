// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the MIT License.

namespace idunno.Security.SsrfTests;

public class SsrfTests
{
    [Theory]
    [InlineData("example.com")]
    [InlineData("www.example.com")]
    public void IsUnsafeUriReturnsFalseForGoodUris(string host)
    {
        Assert.False(Ssrf.IsUnsafeUri(new Uri($"http://{host}/")));
    }
}
