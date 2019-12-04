use libsolid_rs;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

use std::path::PathBuf;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
pub(crate) struct Args {
    #[structopt(subcommand)]
    pub(crate) cmd: crate::command::Command,
}

pub(crate) mod command {
    use super::*;

    #[derive(Debug, StructOpt)]
    pub(crate) enum Command {
        State(state::State),
        Login(login::Login),
        Fetch(fetch::Fetch),
        // TODO: logout, list?, create, update?, more?
    }

    pub(crate) mod state {
        use super::*;

        static HOME_STORE_DIR: &str = ".config/solid-cli/store";

        fn parse_store_dir(s: &str) -> Result<PathBuf> {
            if s.is_empty() {
                let home = dirs::home_dir()
                    .ok_or("store_dir not provided and home directory not found")?;
                Ok(home.join(HOME_STORE_DIR))
            } else {
                Ok(s.into())
            }
        }

        #[derive(Debug, StructOpt)]
        pub(crate) struct State {
            #[structopt(long, default_value = "", parse(try_from_str = parse_store_dir))]
            pub(super) store_dir: PathBuf,

            #[structopt(subcommand)]
            pub(super) state_type: StateType,
        }

        #[derive(Debug, StructOpt)]
        pub(crate) enum StateType {
            List,
            Info { name: String },
            Store { name: String },
            Restore { name: String },
        }
    }

    pub(crate) mod login {
        use super::*;

        #[derive(Debug, StructOpt)]
        pub(crate) struct Login {}
    }

    pub(crate) mod fetch {
        use super::*;

        #[derive(Debug, StructOpt)]
        pub(crate) struct Fetch {
            url: String,
        }
    }
}

#[paw::main]
fn main(args: Args) -> Result<()> {
    match args.cmd {
        // command::Command::State(state) => {
        //     println!("{:#?}", state);
        // }
        unhandled => println!("Command not handled: {:#?}", unhandled),
    }

    Ok(())
}
