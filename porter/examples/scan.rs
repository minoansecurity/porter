use porter::scan;

fn main() {
    for p in scan().unwrap() {
        println!("port {}: {} (pid {})", p.port, p.process, p.pid);
    }
}
