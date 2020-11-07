use std::path::PathBuf;

use structopt::StructOpt;
use syringe::error::SyringeError;
use syringe::RunningInjector;

#[derive(Debug, StructOpt)]
#[structopt(name = "Syringe", about = "A DLL injection utility")]
struct Opt {
    #[structopt(subcommand)]
    locate_from: Command,
}

#[derive(Debug, StructOpt)]
enum Command {
    #[structopt(about = "Specify process by executable name")]
    Exe { name: String, dll_path: PathBuf },
    #[structopt(about = "Specify process by process ID")]
    Pid { pid: u32, dll_path: PathBuf },
}

fn main() -> Result<(), SyringeError> {
    let opts = Opt::from_args();

    let injector = match opts.locate_from {
        Command::Exe { name, dll_path } => RunningInjector::from_exe_name(&name, dll_path),
        Command::Pid { pid, dll_path } => RunningInjector::new(pid, dll_path),
    };
    unsafe {
        if let Err(e) = injector?.inject() {
            println!("{}", e);
        }
    }

    return Ok(());
}
