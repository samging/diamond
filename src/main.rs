mod backend;
mod dec_enc;
use anyhow::anyhow;
use colored::Colorize;
mod helpers;
mod test;
use rustyline::{DefaultEditor, error::ReadlineError};

use crate::{
    backend::{
        parser::{Token, parse_input},
        safe::{AnyHowErrHelper, Checkers},
    },
    dec_enc::generate_password,
};

fn main() -> anyhow::Result<()> {
    loop {
        if interface().is_err() {
            continue;
        }
    }
}

fn interface() -> anyhow::Result<()> {
    let mut rl = DefaultEditor::new()?;

    loop {
        let data = match rl.readline("[obsidian]~>") {
            Ok(o) => o,
            Err(e) => match e {
                ReadlineError::Eof => break Err(anyhow!("Eof/ Ctrl+C")),
                _ => break Err(anyhow!("{e}")),
            },
        };

        let data = parse_input(data)?;

        match data.get_token(&0)?.trim() {
            "add" => {
                helpers::helpers_fn::add_helper(None, 1, &data)?;
            }
            "get" => {
                helpers::helpers_fn::get_helper(None, 1, &data)?;
            }

            "help" => {
                match data.get_token(&1)?.trim() {
                    "--add" => {
                        println!(
                            ">>{}: [{}] [{}] [{}] [{}] [{}] [{}] [{}]",
                            "Usage".bright_green().bold(),
                            "obsidian".bright_blue().bold(),
                            "add".bright_yellow().bold(),
                            "username/email".bright_yellow().bold(),
                            "obsidian".bright_yellow().bold(),
                            "id".bright_yellow().bold(),
                            "master-key".bright_yellow().bold(),
                            "add-password".bright_yellow().bold(),
                        );
                    }
                    "--get" => {
                        println!(
                            ">>{}: [{}] [{}] [{}] [{}]",
                            "Usage".bright_green().bold(),
                            "obsidian".bright_blue().bold(),
                            "get".bright_yellow().bold(),
                            "id".bright_yellow().bold(),
                            "master-key".bright_yellow().bold()
                        );
                    }
                    "--remove" => {
                        println!(
                            ">>{}: [{}] [{}] [{}] [{}]",
                            "Usage".bright_green().bold(),
                            "obsidian".bright_blue().bold(),
                            "remove".bright_yellow().bold(),
                            "id".bright_yellow().bold(),
                            "action-password".bright_yellow().bold()
                        );
                    }
                    "--list" => {
                        println!(
                            ">>{}: [{}] [{}] [{}]",
                            "Usage".bright_green().bold(),
                            "obsidian".bright_blue().bold(),
                            "list".bright_yellow().bold(),
                            "action-password".bright_yellow().bold()
                        );
                    }
                    "--search" => {
                        println!(
                            ">>{}: [{}] [{}] [{}] [{}]",
                            "Usage".bright_green().bold(),
                            "obsidian".bright_blue().bold(),
                            "search".bright_yellow().bold(),
                            "id".bright_yellow().bold(),
                            "action-password".bright_yellow().bold(),
                        );
                    }
                    "--change" => {
                        println!(
                            ">>{}: [{}] [{}] [{}] [{}] [{}] [{}] [{}]",
                            "Usage".bright_green().bold(),
                            "obsidian".bright_blue().bold(),
                            "change".bright_yellow().bold(),
                            "id".bright_yellow().bold(),
                            "username/email".bright_yellow().bold(),
                            "password".bright_yellow().bold(),
                            "master-key".bright_yellow().bold(),
                            "action-password".bright_yellow().bold(),
                        );
                    }
                    "--clear" => {
                        println!(
                            ">>{}: [{}] [{}]",
                            "Usage".bright_green().bold(),
                            "obsidian".bright_blue().bold(),
                            "clear".bright_yellow().bold(),
                        );
                    }
                    "--exit" => {
                        println!(
                            ">>{}: [{}] [{}]",
                            "Usage".bright_green().bold(),
                            "obsidian".bright_blue().bold(),
                            "exit".bright_yellow().bold(),
                        );
                    }
                    "-l" => {
                        helpers::helpers_fn::help_helper_1()?;
                    }
                    _ => {
                        if !data.get_token(&1)?.is_empty() {
                            println!(
                                ">> The flag [{}] you used is not vaild flag please use [{} -l] to check all the available flags",
                                data.get_token(&1)?.bright_red().bold(),
                                "help".bright_yellow().bold()
                            )
                        }
                        continue;
                    }
                }
                continue;
            }
            "list" => {
                helpers::helpers_fn::list_helper(None, 1, &data)?;
            }
            "remove" => {
                helpers::helpers_fn::remove_helper(None, 1, &data)?;
            }
            "search" => {
                helpers::helpers_fn::search_helper(None, 1, &data)?;
            }
            "change" => {
                helpers::helpers_fn::change_helper(None, 1, &data)?;
            }
            "external" => match data.get_token(&2)?.trim() {
                "add" => {
                    let ef = data
                        .get_token(&1)
                        .checker("external file/path".to_string())
                        .pe();

                    if let Ok(ef) = ef {
                        helpers::helpers_fn::add_helper(Some(&ef), 3, &data)?;
                    }
                }
                "get" => {
                    let ef = data
                        .get_token(&1)
                        .checker("external file/path".to_string())
                        .pe();

                    if let Ok(ef) = ef {
                        helpers::helpers_fn::get_helper(Some(&ef), 3, &data)?;
                    }
                }
                "list" => {
                    let ef = data
                        .get_token(&1)
                        .checker("external file/path".to_string())
                        .pe();

                    if let Ok(ef) = ef {
                        helpers::helpers_fn::list_helper(Some(&ef), 3, &data)?;
                    }
                }
                "remove" => {
                    let ef = data
                        .get_token(&1)
                        .checker("external file/path".to_string())
                        .pe();

                    if let Ok(ef) = ef {
                        helpers::helpers_fn::remove_helper(Some(&ef), 3, &data)?;
                    }
                }
                "search" => {
                    let ef = data
                        .get_token(&1)
                        .checker("external file/path".to_string())
                        .pe();

                    if let Ok(ef) = ef {
                        helpers::helpers_fn::search_helper(Some(&ef), 3, &data)?;
                    }
                }
                "change" => {
                    let ef = data
                        .get_token(&1)
                        .checker("external file/path".to_string())
                        .pe();

                    if let Ok(ef) = ef {
                        helpers::helpers_fn::change_helper(Some(&ef), 3, &data)?;
                    }
                }
                "help" => match data.get_token(&3)?.trim() {
                    "--add" => {
                        println!(
                            ">>{}: [{}] [{}] [{}] [{}] [{}] [{}] [{}] [{}] [{}]",
                            "Usage".bright_green().bold(),
                            "obsidian".bright_blue().bold(),
                            "external".bright_yellow().bold(),
                            "add".bright_yellow().bold(),
                            "username/email".bright_yellow().bold(),
                            "obsidian".bright_yellow().bold(),
                            "id".bright_yellow().bold(),
                            "master-key".bright_yellow().bold(),
                            "add-password".bright_yellow().bold(),
                            "path/name".bright_yellow().bold(),
                        );
                    }
                    "--get" => {
                        println!(
                            ">>{}: [{}] [{}] [{}] [{}] [{}] [{}]",
                            "Usage".bright_green().bold(),
                            "obsidian".bright_blue().bold(),
                            "external".bright_yellow().bold(),
                            "get".bright_yellow().bold(),
                            "id".bright_yellow().bold(),
                            "master-key".bright_yellow().bold(),
                            "path/name".bright_yellow().bold(),
                        );
                    }
                    "--remove" => {
                        println!(
                            ">>{}: [{}] [{}] [{}] [{}] [{}] [{}]",
                            "Usage".bright_green().bold(),
                            "obsidian".bright_blue().bold(),
                            "external".bright_yellow().bold(),
                            "remove".bright_yellow().bold(),
                            "id".bright_yellow().bold(),
                            "action-password".bright_yellow().bold(),
                            "path/name".bright_yellow().bold(),
                        );
                    }
                    "--list" => {
                        println!(
                            ">>{}: [{}] [{}] [{}] [{}] [{}]",
                            "Usage".bright_green().bold(),
                            "obsidian".bright_blue().bold(),
                            "external".bright_yellow().bold(),
                            "list".bright_yellow().bold(),
                            "action-password".bright_yellow().bold(),
                            "path/name".bright_yellow().bold()
                        );
                    }
                    "--search" => {
                        println!(
                            ">>{}: [{}] [{}] [{}] [{}] [{}] [{}]",
                            "Usage".bright_green().bold(),
                            "obsidian".bright_blue().bold(),
                            "external".bright_yellow().bold(),
                            "search".bright_yellow().bold(),
                            "id".bright_yellow().bold(),
                            "action-password".bright_yellow().bold(),
                            "path/name".bright_yellow().bold()
                        );
                    }
                    "--change" => {
                        println!(
                            ">>{}: [{}] [{}] [{}] [{}] [{}] [{}] [{}] [{}] [{}]",
                            "Usage".bright_green().bold(),
                            "obsidian".bright_blue().bold(),
                            "external".bright_yellow().bold(),
                            "change".bright_yellow().bold(),
                            "id".bright_yellow().bold(),
                            "username/email".bright_yellow().bold(),
                            "password".bright_yellow().bold(),
                            "master-key".bright_yellow().bold(),
                            "action-password".bright_yellow().bold(),
                            "path/name".bright_yellow().bold(),
                        );
                    }
                    "-l" => {
                        helpers::helpers_fn::help_helper_1()?;
                    }
                    _ => {
                        if !data.get_token(&2)?.is_empty() {
                            println!(
                                ">> The flag [{}] you used is not vaild flag please use [{} -l] to check all the available flags",
                                data.get_token(&2)?.bright_red().bold(),
                                "help".bright_yellow().bold()
                            )
                        }
                        continue;
                    }
                },
                _ => {
                    if !data.get_token(&1)?.is_empty() {
                        println!(
                            ">> The command [{}] you used is not vaild command please use [{}] to check all the available commands",
                            data.get_token(&1)?.bright_red().bold(),
                            "help".bright_yellow().bold()
                        )
                    }
                }
            },
            "exit" => {
                std::process::exit(0);
            }
            "clear" => {
                #[cfg(unix)]
                {
                    std::process::Command::new("clear").status()?;
                }
                #[cfg(windows)]
                {
                    std::process::Command::new("cmd").args(["/C" , "cls"]).status()?;
                }
                continue;
            }
            "gp" => {
                generate_password().pe()?;
            }
            _ => {
                if !data.get_token(&0)?.is_empty() {
                    println!(
                        ">> The command [{}] you used is not vaild command please use [{} -l] to check all the available commands",
                        data.get_token(&0)?.bright_red().bold(),
                        "help".bright_yellow().bold()
                    )
                }
            }
        }
        return Ok(());
    }
}
