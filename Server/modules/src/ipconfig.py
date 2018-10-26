import System
import System.Net.IPAddress as IPAddress
import System.Net.NetworkInformation as NetworkInformation

def convertNumToIP(ipNum):
    ipBytes = IPAddress.Parse(ipNum.ToString()).GetAddressBytes()
    System.Array.Reverse(ipBytes)
    return IPAddress(ipBytes).ToString()

def configSummary():
    gp = NetworkInformation.IPGlobalProperties.GetIPGlobalProperties()
    details = (gp.HostName, gp.DomainName, gp.NodeType, gp.DhcpScopeName, gp.IsWinsProxy)
    summary = """\nComputer Name: {0}
    Domain Name: {1}
    Node Type: {2}
    DHCP Scope: {3}
    WINS Proxy: {4}\n""".format(*details)
    return summary

def interfaceSummary(iface):
    properties = iface.GetIPProperties()
    physAddr = iface.GetPhysicalAddress().ToString()
    physAddr = ":".join(x+y for x,y in zip(physAddr[::2], physAddr[1::2]))
    uniAddrs = ", ".join([uni.Address.ToString() for uni in properties.UnicastAddresses if uni.Address.AddressFamily.ToString() == "InterNetwork"])
    multiAddrs = ", ".join([multi.Address.ToString() for multi in properties.MulticastAddresses if multi.Address.AddressFamily.ToString() == "InterNetwork"])
    dhcpAddrs = ", ".join([convertNumToIP(dhcp.Address) for dhcp in properties.DhcpServerAddresses])
    
    try:
        dnsAddrs = ", ".join([convertNumToIP(dns.Address) for dns in properties.DnsAddresses])
    except Exception:
        dnsAddrs = ""

    gwAddrs = ", ".join([gw.Address.ToString() for gw in properties.GatewayAddresses])

    details = (iface.Name, iface.NetworkInterfaceType, iface.Description, physAddr, uniAddrs, multiAddrs, dhcpAddrs, dnsAddrs, properties.DnsSuffix, gwAddrs)
    summary = '''\nName: {0}
    Type: {1}
    Description: {2}
    Physical Address: {3}
    IP Addresses: {4}
    Multicast Addresses: {5}
    DHCP Addresses: {6}
    DNS Addresses: {7}
    DNS Suffix: {8}
    Gateway Addresses: {9}\n'''.format(*details)
    return summary

def ipconfig():
    response = configSummary()
    interfaces = NetworkInformation.NetworkInterface.GetAllNetworkInterfaces()
    for iface in interfaces:
        response += interfaceSummary(iface)

    print response

ipconfig()