mod model;
mod net;
mod identify;

fn main() {
    let priv_level = net::raw::detect_privilege();
    println!("Privilege: {}", priv_level);

    let iface = net::interface::pick_interface(None);
    match iface {
        Some(i) => println!("Interface: {} IP: {} MAC: {} Subnet: {}", i.name, i.ip, i.mac, i.network),
        None => println!("No suitable interface found"),
    }

    let mac = pnet::util::MacAddr::new(0xAC, 0xBC, 0x32, 0x00, 0x00, 0x00);
    println!("OUI {}: {:?}", mac, identify::oui::lookup_vendor(&mac));
    println!("iPhone15,2: {:?}", identify::apple::lookup_model("iPhone15,2"));
}
