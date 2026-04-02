use pnet::util::MacAddr;

include!(concat!(env!("OUT_DIR"), "/oui_table.rs"));

pub fn lookup_vendor(mac: &MacAddr) -> Option<&'static str> {
    let key = format!("{}_{}_{}", mac.0, mac.1, mac.2);
    OUI_TABLE.get(key.as_str()).copied()
}

pub fn is_randomized_mac(mac: &MacAddr) -> bool {
    mac.0 & 0x02 != 0
}
