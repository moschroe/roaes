use roaes::{RoaesSink, RoaesSource};
use std::io::{stdin, stdout, ErrorKind as IOErrorKind, Write};

const USAGE: &str = r###"USAGE: roaes enc|dev <key>

decrypts files encrypted in CBC mode with the TWRP-flavoured oaes binary
reads stdin and writes to stdout, expects encryption key as single argument
"###;

fn main() {
    env_logger::init();
    let mut args = std::env::args().skip(1);

    let do_encrypt = match args.next() {
        None => {
            eprint!("{}", USAGE);
            return;
        }
        Some(s) if s == "enc" => true,
        Some(s) if s == "dec" => false,
        Some(_s) => {
            eprint!("{}", USAGE);
            return;
        }
    };

    let key = match args.next() {
        None => {
            eprint!("{}", USAGE);
            return;
        }
        Some(s) if s.is_empty() => {
            eprint!("{}", USAGE);
            return;
        }
        Some(s) => s,
    };

    let sin = stdin();
    let mut sin_lock = sin.lock();

    let sout = stdout();
    let mut sout_lock = sout.lock();

    let copied;
    let mut pipe = false;

    if do_encrypt {
        let mut roas =
            RoaesSink::new(sout_lock, key.as_bytes()).expect("unable to create RoaesSink, sorry!");

        copied = std::io::copy(&mut sin_lock, &mut roas)
            .and_then(|copied| roas.flush().map(|()| copied))
            .or_else(|err_io| {
                if err_io.kind() == IOErrorKind::BrokenPipe {
                    pipe = true;
                    Ok(0)
                } else {
                    Err(err_io)
                }
            })
            .expect("unable to copy data from input to output");
    } else {
        let mut roas = RoaesSource::new(sin_lock, key.as_bytes())
            .expect("unable to create RoaesSource, sorry!");

        copied = std::io::copy(&mut roas, &mut sout_lock)
            .and_then(|copied| sout_lock.flush().map(|()| copied))
            .or_else(|err_io| {
                if err_io.kind() == IOErrorKind::BrokenPipe {
                    pipe = true;
                    Ok(0)
                } else {
                    Err(err_io)
                }
            })
            .expect("unable to copy data from input to output");
    }

    if !pipe {
        eprintln!("copied {} bytes", copied);
    }
}
