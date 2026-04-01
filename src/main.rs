mod model;
mod net;

fn main() {
    let priv_level = net::raw::detect_privilege();
    println!("Privilege: {}", priv_level);

    let iface = net::interface::pick_interface(None);
    match iface {
        Some(i) => println!("Interface: {} IP: {} MAC: {} Subnet: {}", i.name, i.ip, i.mac, i.network),
        None => println!("No suitable interface found"),
    }
}
