--/Applications/Wireshark.app/Contents/MacOS/Wireshark -X lua_script:reli.lua rek3.pcap
local function checksum(data)
    local data_copy = data
    if math.fmod(data_copy:len(), 2) == 1 then data_copy:set_size(data_copy:len()+1) end
    local sum = 0
    local rounds = data_copy:len()/2
    data_copy:set_index(14,0)
    data_copy:set_index(15,0)
    for i = 1, rounds do
        idx = i - 1
        sum = sum + data_copy:get_index(idx*2+0)*256 + data_copy:get_index(idx*2+1)
    end
    while math.floor(sum / 65536) > 0 do
       sum = (sum % 65536) + (math.floor(sum / 65536))
    end
    return 65535 - sum
end


reli_proto = Proto("reli", "Reliable Protocol")
function reli_proto.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "RELI"
    length = buffer:len()
    data_len = length-16
    local subtree = tree:add(reli_proto, buffer(), "Reliable Protocol Data")
    subtree:add(buffer(0,4), "Sequence Number:" .. buffer(0,4):uint())
    subtree:add(buffer(4,4), "Acknowledge Number:" .. buffer(4,4):uint())
    subtree:add(buffer(8,4), "Receive Window Size:" .. buffer(8,4):uint())
    subtree:add(buffer(12,2), "Reserved&Flags: 0x" .. buffer(12,2))
    current_pkt_checksum = checksum(buffer(0,length):bytes())
    if buffer(14,2):uint() == current_pkt_checksum then
        subtree:add(buffer(14,2), "Checksum sent: 0x" .. buffer(14,2) .. ", Should be:" .. ('0x%x'):format(current_pkt_checksum) .. ", [CORRECT]")
    else
        subtree:add(buffer(14,2), "Checksum sent: 0x" .. buffer(14,2) .. ", Should be:" .. ('0x%x'):format(current_pkt_checksum) .. ", [INCORRECT]")
    end
    if data_len>0 then subtree:add(buffer(16,data_len), "data:" .. buffer(16,data_len):string()) end
end
udp_table = DissectorTable.get("udp.port")
udp_table:add(50001, reli_proto)