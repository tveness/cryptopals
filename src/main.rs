use anyhow::{anyhow, Result};
const HELP: &str = "
USAGE:
    -c [CHALLENGE_NUMBER]

FLAGS:
    -h, --help           Prints help information
";

mod dh;
mod set1;
mod set2;
mod set3;
mod set4;
mod set5;
mod set6;
mod set7;
mod set8;
mod stream;
mod utils;

fn parse_args() -> Result<u64, pico_args::Error> {
    let mut pargs = pico_args::Arguments::from_env();

    if pargs.contains(["-h", "--help"]) {
        print!("{}", HELP);
        std::process::exit(0);
    }

    let challenge = pargs.value_from_str("-c")?;

    Ok(challenge)
}

fn main() -> Result<()> {
    let challenge = parse_args()?;

    match challenge {
        c @ 1..=8 => set1::run(c),
        c @ 9..=16 => set2::run(c),
        c @ 17..=24 => set3::run(c),
        c @ 25..=32 => set4::run(c),
        c @ 33..=40 => set5::run(c),
        c @ 41..=48 => set6::run(c),
        c @ 49..=56 => set7::run(c),
        c @ 57..=66 => set8::run(c),
        _ => Err(anyhow!("Invalid challenge number")),
    }?;
    Ok(())
}
