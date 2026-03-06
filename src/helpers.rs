pub mod helpers_fn {
    use crate::backend::{
        parser::Token,
        safe::{
            AnyHowErrHelper, Checkers, FileChecker, MasterKeyV, PasswordChecker, action_password,
            does_not_e,
        },
    };
    use crate::dec_enc::{_pre_, add, change, get, home_dirr, list, pre_add, remove, search};
    use anyhow::anyhow;
    use std::fs;

    pub fn add_helper(ef: Option<&String>, index: usize, data: &Vec<String>) -> anyhow::Result<()> {
        let mut index = index;

        let username_email = data
            .get_token(&index)
            .checker("username/email".to_string())
            .pe();

        index += 1;
        let password = data.get_token(&index).checker("password".to_string()).pe();
        index += 1;
        let id = data.get_token(&index).checker("url/app".to_string()).pe();
        index += 1;
        let master_key = data
            .get_token(&index)
            .checker("master-key".to_string())?
            .master_key_checker()
            .pe()?
            .check_password_(&"master-key".to_string(), username_email.as_ref())
            .pe();
        index += 1;
        let ac_password = data
            .get_token(&index)
            .checker("action-password".to_string())?
            .check_password_(&"action-password".to_string(), username_email.as_ref())
            .pe();

        let res = if ac_password.is_ok() {
            action_password(&ac_password?).pe()
        } else {
            return Err(anyhow!("missing action-password"));
        };

        if res.is_ok() {
            if let (Ok(us), Ok(p), Ok(u), Ok(m)) = (username_email, password, &id, master_key)
            {
                if fs::File::open(
                    home_dirr()?
                        .join("obsidian/obs.json")
                        .to_string_lossy()
                        .to_string(),
                )
                .is_err_and(|s| s.kind() == std::io::ErrorKind::NotFound)
                {
                    _pre_()?;
                    pre_add(&us, &u, &p, &m, ef).pe()?;
                }
                if ef.is_some() {
                    if let Some(ef) = ef {
                        if fs::File::open(home_dirr()?.join(ef)).is_err() {
                            _pre_()?;
                            pre_add(&us.to_string(), &u, &p, &m, Some(ef)).pe()?;
                        }
                    }
                } else {
                    let u = &u.to_string().check_existing_ids(u, ef).pe();
                    if let Ok(u) = u {
                        add(&us.to_string(), &u, &p, &m, ef).pe()?;
                    }
                }
            }
        }
        Ok(())
    }

    pub fn get_helper(ef: Option<&String>, index: usize, data: &Vec<String>) -> anyhow::Result<()> {
        let mut indexx = index;

        let id = data.get_token(&indexx).checker("app/url".to_string()).pe();
        indexx += 1;
        let master_key = data
            .get_token(&indexx)
            .checker("master-key".to_string())?
            .master_key_checker()
            .pe();
        indexx += 1;
        let action_pass = data
            .get_token(&indexx)
            .checker("action-password".to_string())
            .pe();

        let res = if action_pass.is_ok() {
            action_password(&action_pass?).pe()
        } else {
            return Err(anyhow!("missing action-password"));
        };

        does_not_e(
            &id
                .as_ref()
                .map_err(|_| anyhow!("moving url/app error!"))?
                .to_string(),
            index,
            &data,
            ef,
        )
        .pe()?;

        if res.is_ok() {
            if let (Ok(o), Ok(p)) = (id, master_key) {
                get(o, p, ef).pe()?
            }
        }
        Ok(())
    }

    pub fn list_helper(
        ef: Option<&String>,
        index: usize,
        data: &Vec<String>,
    ) -> anyhow::Result<()> {
        let ac_pass = data
            .get_token(&index)
            .checker("action-password".to_string())
            .pe();

        let res = if ac_pass.is_ok() {
            action_password(&ac_pass?).pe()
        } else {
            return Err(anyhow!("missing action-password"));
        };

        if res.is_ok() {
            list(ef).pe()?;
        }
        Ok(())
    }

    pub fn remove_helper(
        ef: Option<&String>,
        index: usize,
        data: &Vec<String>,
    ) -> anyhow::Result<()> {
        let mut indexx = index;

        let id = data.get_token(&indexx).checker("url/app".to_string()).pe();
        indexx += 1;
        let ac_password = data
            .get_token(&indexx)
            .checker("action password".to_string())
            .pe();

        let res = if ac_password.is_ok() {
            action_password(&ac_password?).pe()
        } else {
            return Err(anyhow!("missing action-password"));
        };

        does_not_e(
            &id
                .as_ref()
                .map_err(|_| anyhow!("moving url/app error!"))?
                .to_string(),
            index,
            &data,
            ef,
        )
        .pe()?;

        if res.is_ok() {
            if let Ok(o) = id {
                remove(&o, ef)?;
            }
        }
        Ok(())
    }

    pub fn search_helper(
        ef: Option<&String>,
        index: usize,
        data: &Vec<String>,
    ) -> anyhow::Result<()> {
        let mut indexx = index;

        let id = data.get_token(&indexx).checker("url/app".to_string()).pe();
        indexx += 1;
        let ac_password = data
            .get_token(&indexx)
            .checker("action password".to_string())
            .pe();

        let res = if ac_password.is_ok() {
            action_password(&ac_password?).pe()
        } else {
            return Err(anyhow!("missing action-password"));
        };

        does_not_e(
            &id
                .as_ref()
                .map_err(|_| anyhow!("moving url/app error!"))?
                .to_string(),
            index,
            &data,
            ef,
        )
        .pe()?;

        if res.is_ok() {
            if let Ok(o) = id {
                search(&o, ef).pe()?
            }
        }
        Ok(())
    }

    pub fn change_helper(
        ef: Option<&String>,
        index: usize,
        data: &Vec<String>,
    ) -> anyhow::Result<()> {
        let mut indexx = index;

        let id = data.get_token(&indexx).checker("url/app".to_string()).pe();
        indexx += 1;
        let username_email = data
            .get_token(&indexx)
            .checker("username/email".to_string())
            .pe();
        indexx += 1;
        let passwoed = data.get_token(&indexx).checker("password".to_string()).pe();
        indexx += 1;
        let master_key = data
            .get_token(&indexx)
            .checker("master-key".to_string())
            .pe()?
            .master_key_checker()
            .pe()?
            .check_password_(&"master-key".to_string(), username_email.as_ref());
        indexx += 1;
        let ac_password = data
            .get_token(&indexx)
            .checker("action-password".to_string())
            .pe();

        let res = if ac_password.is_ok() {
            action_password(&ac_password?)
        } else {
            return Err(anyhow!("missing action-password"));
        };

        does_not_e(
            &id
                .as_ref()
                .map_err(|_| anyhow!("moving url/app error!"))?
                .to_string(),
            index,
            &data,
            ef,
        )
        .pe()?;

        if res.is_ok() {
            if let (Ok(ue), Ok(pw), Ok(mk)) = (username_email, passwoed, master_key) {
                change(
                    &data.get_token(&index).checker("url/app".to_string())?,
                    ef,
                    &mk,
                    &pw,
                    &ue,
                )
                .pe()?
            }
        }
        Ok(())
    }

    pub fn help_helper_1() -> anyhow::Result<()> {
        use colored::Colorize;

        println!(
            ">>[{}] --[{}]",
            "help".bright_purple().bold(),
            "add/get/remove/search/clear/exit/list/change"
                .bright_yellow()
                .bold()
        );
        println!(
            ">> <{}: used to add passwords and so on> / <{}: used to get data>",
            "add".bright_purple().bold(),
            "get".bright_purple().bold()
        );
        println!(
            ">> <{}: used to remove data from the file> / <{}: used to search for data by there url/app name>",
            "remove".bright_purple().bold(),
            "search".bright_purple().bold()
        );
        println!(
            ">> <{}: used to clear the term> / <{}: used to exit the program>",
            "clear".bright_purple().bold(),
            "exit".bright_purple().bold()
        );
        println!(
            ">> <{}: used to list all the data> / <{}: used to change data using there url/app name>",
            "list".bright_purple().bold(),
            "change".bright_purple().bold()
        );

        println!(
            ">> <{}: used to list all the data> / <{}: used to change data using there url/app name>",
            "list".bright_purple().bold(),
            "change".bright_purple().bold()
        );

        println!(
            ">> <{}: used to generate new password>",
            "gp".bright_purple().bold(),
        );
        Ok(())
    }
}
