## .pdor
Used to store entries for `--read`'ing.
### Header
`0xCAFE` - `4 bytes`.
`Major Ver.` - `2 bytes`. (1)
`Minor Ver.` - `2 bytes`. (0)
### Packet
```cpp
struct Entry {
    std::uint64_t ts; // Timestamp (seconds)
    std::array<char, 6> shaddr; // Source Hardware Address
    std::array<char, 6> thaddr; // Target Hardware Address
    std::uint16_t eth_proto; // Protocol used on L3 Layer

    std::array<char, 16> saddr; // Either IPv4 or IPv6
    std::array<char, 16> taddr; // Either IPv4 or IPv6
    std::uint8_t ip_proto; // Protocol used on L4 Layer

    std::uint16_t sport; // Source port
    std::uint16_t tport; // Dest. port
};
```
