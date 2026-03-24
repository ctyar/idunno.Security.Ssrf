// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the MIT License.

using System.Net;

namespace idunno.Security.SsrfTests;

public class IsUnsafeIpAddressTests
{
    [Theory]
    [InlineData("104.18.26.120")]
    [InlineData("104.18.27.120")]
    [InlineData("[2620:1ec:bdf::69]")]
    [InlineData("[2620:1ec:46::69]")]
    public void ReturnsFalseForGoodIpAddresses(string ipAddressAsString)
    {
        Assert.False(Ssrf.IsUnsafeIpAddress(IPAddress.Parse(ipAddressAsString)));
    }

    [Theory]
    [InlineData("104.18.26.120")]
    [InlineData("104.18.27.120")]
    [InlineData("[2620:1ec:bdf::69]")]
    [InlineData("[2620:1ec:46::69]")]
    public void ReturnsTrueForGoodIpAddressesIfTheyAreInTheSpecifiedAdditionalNetworks(string ipAddressAsString)
    {
        Assert.True(Ssrf.IsUnsafeIpAddress(
            ipAddress: IPAddress.Parse(ipAddressAsString),
            additionalNetworks:
            [
                IPNetwork.Parse("104.16.0.0/12"),
                IPNetwork.Parse("2620:1ec::/36")
            ]));
    }


    // TODO: Test IPs in predefined networks



    [Fact]
    public void ReturnsTrueForLoopbackIpAddresses()
    {
        Assert.True(Ssrf.IsUnsafeIpAddress(IPAddress.Loopback));
        Assert.True(Ssrf.IsUnsafeIpAddress(IPAddress.IPv6Loopback));
    }

    [Fact]
    public void ReturnsTrueForUnspecifiedIpAddresses()
    {
        Assert.True(Ssrf.IsUnsafeIpAddress(IPAddress.None));
        Assert.True(Ssrf.IsUnsafeIpAddress(IPAddress.IPv6None));
    }

    [Theory]
    // See https://www.iana.org/assignments/ipv6-multicast-addresses/ipv6-multicast-addresses.xhtml
    // Node-Local Scope Multicast Addresses
    [InlineData("ff01:0:0:0:0:0:0:1")]
    [InlineData("ff01:0:0:0:0:0:0:2")]
    [InlineData("ff01:0:0:0:0:0:0:c")]
    [InlineData("ff01:0:0:0:0:0:0:fa")]
    [InlineData("ff01:0:0:0:0:0:0:fb")]
    [InlineData("ff01:0:0:0:0:0:0:fc")]
    [InlineData("ff01:0:0:0:0:0:0:fd")]
    [InlineData("ff01:0:0:0:0:0:0:100")]
    [InlineData("ff01:0:0:0:0:0:0:178")]
    [InlineData("ff01:0:0:0:0:0:0:181")]
    [InlineData("ff01:0:0:0:0:0:0:184")]
    [InlineData("ff01:0:0:0:0:0:0:18c")]
    [InlineData("ff01:0:0:0:0:0:0:201")]
    [InlineData("ff01:0:0:0:0:0:0:202")]
    [InlineData("ff01:0:0:0:0:0:0:204")]
    [InlineData("ff01:0:0:0:0:0:0:2c0")]
    [InlineData("ff01:0:0:0:0:0:0:2ff")]
    [InlineData("ff01:0:0:0:0:0:0:300")]
    [InlineData("ff01:0:0:0:0:0:0:400")]
    [InlineData("ff01:0:0:0:0:0:0:4ff")]
    [InlineData("ff01:0:0:0:0:0:0:3486")]
    [InlineData("ff01:0:0:0:0:0:0:bac0")]
    [InlineData("ff01:0:0:0:0:0:1:1000")]
    [InlineData("ff01:0:0:0:0:0:2:0")]
    [InlineData("ff01:0:0:0:0:0:4:ffff")]
    [InlineData("ff01:0:0:0:0:0:b:0")]
    [InlineData("ff01:0:0:0:0:0:b:ffff")]
    [InlineData("ff01:0:0:0:0:db8::")]
    [InlineData("ff01:0:0:0:0:0:ee10:0")]
    [InlineData("ff01:0:0:0:0:0:ee10:1f")]

    // Link-Local Scope Multicast Addresses
    [InlineData("ff02:0:0:0:0:0:0:1")]
    [InlineData("ff02:0:0:0:0:0:0:2")]
    [InlineData("ff02:0:0:0:0:0:0:3")]
    [InlineData("ff02:0:0:0:0:0:0:4")]
    [InlineData("ff02:0:0:0:0:0:0:5")]
    [InlineData("ff02:0:0:0:0:0:0:6")]
    [InlineData("ff02:0:0:0:0:0:0:7")]
    [InlineData("ff02:0:0:0:0:0:0:8")]
    [InlineData("ff02:0:0:0:0:0:0:9")]
    [InlineData("ff02:0:0:0:0:0:0:a")]
    [InlineData("ff02:0:0:0:0:0:0:b")]
    [InlineData("ff02:0:0:0:0:0:0:c")]
    [InlineData("ff02:0:0:0:0:0:0:d")]
    [InlineData("ff02:0:0:0:0:0:0:e")]
    [InlineData("ff02:0:0:0:0:0:0:f")]
    [InlineData("ff02:0:0:0:0:0:0:10")]
    [InlineData("ff02:0:0:0:0:0:0:11")]
    [InlineData("ff02:0:0:0:0:0:0:12")]
    [InlineData("ff02:0:0:0:0:0:0:13")]
    [InlineData("ff02:0:0:0:0:0:0:14")]
    [InlineData("ff02:0:0:0:0:0:0:16")]
    [InlineData("ff02:0:0:0:0:0:0:1a")]
    [InlineData("ff02:0:0:0:0:0:0:6a")]
    [InlineData("ff02:0:0:0:0:0:0:6b")]
    [InlineData("ff02:0:0:0:0:0:0:6c")]
    [InlineData("ff02:0:0:0:0:0:0:6d")]
    [InlineData("ff02:0:0:0:0:0:0:6e")]
    [InlineData("ff02:0:0:0:0:0:0:6f")]
    [InlineData("ff02:0:0:0:0:0:0:fa")]
    [InlineData("ff02:0:0:0:0:0:0:fb")]
    [InlineData("ff02:0:0:0:0:0:0:fc")]
    [InlineData("ff02:0:0:0:0:0:0:fd")]
    [InlineData("ff02:0:0:0:0:0:0:100")]
    [InlineData("ff02:0:0:0:0:0:0:178")]
    [InlineData("ff02:0:0:0:0:0:0:181")]
    [InlineData("ff02:0:0:0:0:0:0:184")]
    [InlineData("ff02:0:0:0:0:0:0:18c")]
    [InlineData("ff02:0:0:0:0:0:0:201")]
    [InlineData("ff02:0:0:0:0:0:0:204")]
    [InlineData("ff02:0:0:0:0:0:0:2c0")]
    [InlineData("ff02:0:0:0:0:0:0:300")]
    [InlineData("ff02:0:0:0:0:0:0:400")]
    [InlineData("ff02:0:0:0:0:0:0:4ff")]
    [InlineData("ff02:0:0:0:0:0:0:3486")]
    [InlineData("ff02:0:0:0:0:0:0:a1f7")]
    [InlineData("ff02:0:0:0:0:0:0:bac0")]
    [InlineData("ff02:0:0:0:0:0:1:1")]
    [InlineData("ff02:0:0:0:0:0:1:2")]
    [InlineData("ff02:0:0:0:0:0:1:3")]
    [InlineData("ff02:0:0:0:0:0:1:4")]
    [InlineData("ff02:0:0:0:0:0:1:5")]
    [InlineData("ff02:0:0:0:0:0:1:6")]
    [InlineData("ff02:0:0:0:0:0:1:7")]
    [InlineData("ff02:0:0:0:0:0:1:1000")]
    [InlineData("ff02:0:0:0:0:0:2:0")]
    [InlineData("ff02:0:0:0:0:0:4:ffff")]
    [InlineData("ff02:0:0:0:0:0:b:0")]
    [InlineData("ff02:0:0:0:0:0:b:ffff")]
    [InlineData("ff02:0:0:0:0:1:ff00::")]
    [InlineData("ff02:0:0:0:0:2:ff00::")]
    [InlineData("ff02:0:0:0:0:db8::")]
    [InlineData("ff02:0:0:0:0:0:ee10:0")]
    [InlineData("ff02:0:0:0:0:0:ee10:1f")]

    // Site-Local Scope Multicast Addresses
    [InlineData("ff05:0:0:0:0:0:0:2")]
    [InlineData("ff05:0:0:0:0:0:0:c")]
    [InlineData("ff05:0:0:0:0:0:0:fa")]
    [InlineData("ff05:0:0:0:0:0:0:fb")]
    [InlineData("ff05:0:0:0:0:0:0:fc")]
    [InlineData("ff05:0:0:0:0:0:0:fd")]
    [InlineData("ff05:0:0:0:0:0:0:100")]
    [InlineData("ff05:0:0:0:0:0:0:178")]
    [InlineData("ff05:0:0:0:0:0:0:181")]
    [InlineData("ff05:0:0:0:0:0:0:184")]
    [InlineData("ff05:0:0:0:0:0:0:18c")]
    [InlineData("ff05:0:0:0:0:0:0:201")]
    [InlineData("ff05:0:0:0:0:0:0:202")]
    [InlineData("ff05:0:0:0:0:0:0:204")]
    [InlineData("ff05:0:0:0:0:0:0:206")]
    [InlineData("ff05:0:0:0:0:0:0:2c0")]
    [InlineData("ff05:0:0:0:0:0:0:300")]
    [InlineData("ff05:0:0:0:0:0:0:400")]
    [InlineData("ff05:0:0:0:0:0:0:4ff")]
    [InlineData("ff05:0:0:0:0:0:0:3486")]
    [InlineData("ff05:0:0:0:0:0:0:bac0")]
    [InlineData("ff05:0:0:0:0:0:1:3")]
    [InlineData("ff05:0:0:0:0:0:1:4")]
    [InlineData("ff05:0:0:0:0:0:1:5")]
    [InlineData("ff05:0:0:0:0:0:1:1000")]
    [InlineData("ff05:0:0:0:0:0:2:0")]
    [InlineData("ff05:0:0:0:0:0:4:ffff")]
    [InlineData("ff05:0:0:0:0:0:b:0")]
    [InlineData("ff05:0:0:0:0:0:b:ffff")]
    [InlineData("ff05:0:0:0:0:db8::")]
    [InlineData("ff05:0:0:0:0:0:ee10:0")]
    [InlineData("ff05:0:0:0:0:0:ee10:1f")]
    public void ReturnsTrueForKnownIpv6MulticastAddresses(string ipAddressAsString)
    {
        IPAddress ipAddress = IPAddress.Parse(ipAddressAsString);
        Assert.True(Ssrf.IsUnsafeIpAddress(ipAddress));
    }

    [Theory]
    [InlineData("fe80::1a2b:3cff:fe4d:5e6f")] // Link-local unicast address
    [InlineData("fec0:0000:0000:0000:0000:0000:0000:0001")] // Site-local unicast address
    [InlineData("fe80::1")] // Link-local unicast address
    public void ReturnsTrueForKnownIpv6KnownLocalAddresses(string ipAddressAsString)
    {
        IPAddress ipAddress = IPAddress.Parse(ipAddressAsString);
        Assert.True(Ssrf.IsUnsafeIpAddress(ipAddress));
    }
}
