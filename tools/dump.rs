use clap::Parser;

mod utils;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Path to the ed25519 public key, generated as described by the mktoken
    /// documentation.
    public_key: std::path::PathBuf,

    /// Whether to use the C format for arrays rather than the rust format.
    #[clap(short, long)]
    c: bool
}

fn main() {
    let args = Args::parse();
    let key = utils::read_public_key(&args.public_key);
    if args.c {
        print!("static const unsigned char key[32] = {{");
    } else {
        print!("const KEY: [u8; 32] = [");
    }
    for byte in key.iter() {
        print!(" {:x},", byte);
    }
    if args.c {
        println!("}};");
    } else {
        println!("];");
    }
}
