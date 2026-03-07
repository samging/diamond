use anyhow::anyhow;
use base64::prelude::*;
use colored::Colorize;
use rand::RngExt;
use std::{
    env::home_dir,
    fs,
    io::{Read, Write, stdin, stdout},
    ops::Deref,
    path::PathBuf,
};
use zeroize::Zeroizing;

use aes_gcm::{
    AeadCore, Aes256Gcm, Key, KeyInit, Nonce, aead::{Aead, OsRng, rand_core::RngCore}
};
use argon2::Argon2;
use serde::{Deserialize, Serialize};

use crate::backend::safe::AnyHowErrHelper;

#[derive(Debug, Serialize, Deserialize)]
pub struct Fields {
    pub id: String,
    pub data: String,
}

pub fn home_dirr() -> anyhow::Result<PathBuf> {
    let home_dir = if let Some(h) = home_dir() {
        h
    } else {
        return Err(anyhow!("couldn't find home dir"));
    };

    Ok(home_dir)
}

pub fn _pre_() -> anyhow::Result<()> {
    let home_dir = home_dirr()?;
    fs::create_dir_all(home_dir.join("obsidian").to_string_lossy().to_string())?;
    Ok(())
}

pub fn pre_add(
    username_email: &str,
    id: &str,
    password: &str,
    master_key: &str,
    ef: Option<&String>,
) -> anyhow::Result<()> {
    let password = Zeroizing::new(password.to_string());
    let master_key = Zeroizing::new(master_key.to_string());

    let data = enc(&master_key, &username_email.to_string(), &password)?;

    let data = BASE64_STANDARD.encode(data);

    let cont = Fields {
        id: id.to_string(),
        data: data,
    };

    let vec = vec![cont];

    let json = serde_json::to_string(&vec)?;

    if let Some(o) = ef {
        let json_enc = BASE64_STANDARD.encode(enc_all(json)?);
        fs::write(home_dirr()?.join(o), json_enc)?;
        #[cfg(unix)]
        set_perm_over_file(&home_dirr()?.join(o))?;
    } else {
        let json_enc = BASE64_STANDARD.encode(enc_all( json)?);
        fs::write(home_dirr()?.join("obsidian/obs.json"), json_enc)?;
        #[cfg(unix)]
        set_perm_over_file(&home_dirr()?.join("obsidian/obs.json"))?;
    }

    println!(
        ">>{}: added [{}] [{}]",
        "obsidian".bright_cyan().bold(),
        username_email.to_string().white().bold(),
        id.bright_white().bold()
    );
    Ok(())
}

pub fn add(
    username_email: &str,
    id: &str,
    password: &str,
    master_key: &str,
    ef: Option<&String>,
) -> anyhow::Result<()> {
    let password = Zeroizing::new(password.to_string());
    let master_key = Zeroizing::new(master_key.to_string());

    let mut file = read_json(ef).pe()?;
    let data = BASE64_STANDARD.encode(enc(&master_key, &username_email.to_string(), &password)?);
    let cont = Fields {
        id: id.to_string(),
        data: data,
    };

    file.push(cont);

    let json = serde_json::to_string(&file)?;

    if let Some(o) = ef {
        let enc_json = BASE64_STANDARD.encode(enc_all(json)?);
        fs::write(home_dirr()?.join(o), enc_json)?;
        #[cfg(unix)]
        set_perm_over_file(&home_dirr()?.join(o))?;
    } else {
        let enc_json = BASE64_STANDARD.encode(enc_all(json)?);
        fs::write(home_dirr()?.join("obsidian/obs.json"), enc_json)?;
        #[cfg(unix)]
        set_perm_over_file(&home_dirr()?.join("obsidian/obs.json"))?;
    }

    println!(
        ">>{}: added [{}] [{}]",
        "obsidian".bright_cyan().bold(),
        username_email.to_string().white().bold(),
        id.bright_white().bold()
    );

    Ok(())
}

pub fn get(id: String, master_key: String, ef: Option<&String>) -> anyhow::Result<()> {
    let master_key = Zeroizing::new(master_key);

    let dec = dec(&master_key, &id, ef)?;
    let dec = String::from_utf8(dec)?;
    let decc: Vec<String> = dec.split('|').map(|s| s.to_string()).collect();

    println!(
        ">>{}: got [{}] [{}] [{}]",
        "obsidian".bright_cyan().bold(),
        id.to_string().white().bold(),
        &decc[0].bright_white().bold(),
        &decc[1].bright_white().bold()
    );

    Ok(())
}

pub fn read_json(ef: Option<&String>) -> anyhow::Result<Vec<Fields>> {
    let mut s = String::new();

    let mut o = if let Some(ef) = ef {
        let o = fs::File::open(home_dirr()?.join(ef))?;
        o
    } else {
        let o = fs::File::open(
            home_dirr()?
                .join("obsidian/obs.json")
                .to_string_lossy()
                .to_string(),
        )?;
        o
    };

    o.read_to_string(&mut s)?;
    let dec = BASE64_STANDARD.decode(&s.trim())?;
    let dec_data = dec_all(dec)?;

    if let Ok(vec) = serde_json::from_str::<Vec<Fields>>(&String::from_utf8(dec_data)?) {
        return Ok(vec);
    } else {
        return Err(anyhow!("Couldn't read json file"));
    }
}

fn enc(master_key: &String, username_email: &String, password: &String) -> anyhow::Result<Vec<u8>> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let argon2 = Argon2::default();
    let mut out_master = Zeroizing::new([0u8; 32]);

    argon2
        .hash_password_into(master_key.as_bytes(), &salt, &mut *out_master)
        .map_err(|_| anyhow!("Couldn't hash master key"))?;

    let key = Key::<Aes256Gcm>::from_slice(&*out_master);
    let cip = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let format = Zeroizing::new(format!("{}|{}", username_email, password.to_string()));

    let enc = cip
        .encrypt(&nonce, format.as_bytes())
        .map_err(|_| anyhow!("Couldn't enc data"))?;

    let mut finsh = Vec::new();
    finsh.extend_from_slice(&salt);
    finsh.extend_from_slice(&nonce);
    finsh.extend_from_slice(&enc);

    Ok(finsh)
}

fn dec(master_key: &String, id: &String, ef: Option<&String>) -> anyhow::Result<Vec<u8>> {
    let read_json = read_json(ef)?;

    let data = if let Some(s) = read_json.iter().find(|s| s.id == *id) {
        s.data.trim()
    } else {
        return Err(anyhow!("Couldn't get data"));
    };

    let data = BASE64_STANDARD.decode(data)?;

    let (salt, rest) = data.split_at(16);
    let (nonce_bytes, restt) = rest.split_at(12);

    let argon2 = Argon2::default();
    let mut out_pass = Zeroizing::new([0u8; 32]);

    argon2
        .hash_password_into(master_key.as_bytes(), salt, &mut *out_pass)
        .map_err(|_| anyhow!("Couldn't hash master key"))?;

    let key = Key::<Aes256Gcm>::from_slice(&*out_pass);
    let cip = Aes256Gcm::new(&key);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let dec = cip
        .decrypt(nonce, restt)
        .map_err(|_| anyhow!("Couldn't dec data"))?;

    Ok(dec)
}

pub fn list(ef: Option<&String>) -> anyhow::Result<()> {
    let read_json = read_json(ef)?;

    for i in read_json {
        println!(
            ">>{} id <{}> | data : <{}>",
            "obsidian".bright_cyan().bold(),
            i.id.to_string().bright_white().bold(),
            i.data.to_string().bright_white().bold()
        );
    }

    Ok(())
}

pub fn action_pass_maker(action_pass: &str) -> anyhow::Result<()> {
    fs::create_dir_all(home_dirr()?.join("obsidian/").to_string_lossy().to_string())?;

    fs::File::create(
        home_dirr()?
            .join("obsidian/obs_password.txt")
            .to_string_lossy()
            .to_string(),
    )?;

    #[cfg(unix)]
    set_perm_over_file(&home_dirr()?.join("obsidian/obs_password.txt"))?;

    let ac_pass = action_pass.trim();

    let argon2 = Argon2::default();
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let mut out_ac_pass = Zeroizing::new([0u8; 32]);

    argon2
        .hash_password_into(ac_pass.as_bytes(), &salt, &mut *out_ac_pass)
        .map_err(|_| anyhow!("Couldn't hash the password in argon2"))?;

    let mut vec = Vec::new();
    vec.extend_from_slice(&salt);
    vec.extend_from_slice(&*out_ac_pass);

    let ac_pass = BASE64_STANDARD.encode(vec);

    fs::write(
        home_dirr()?
            .join("obsidian/obs_password.txt")
            .to_string_lossy()
            .to_string(),
        ac_pass,
    )?;
    Ok(())
}

pub fn action_pass_val(action_pass: &str) -> anyhow::Result<()> {
    let mut read = fs::File::open(
        home_dirr()?
            .join("obsidian/obs_password.txt")
            .to_string_lossy()
            .to_string(),
    )?;
    let mut s = String::new();
    read.read_to_string(&mut s)?;

    let s = s.trim();

    let dec_base64 = BASE64_STANDARD.decode(&s.trim())?;

    let (salt, _) = dec_base64.split_at(16);

    let mut out_pass_ac = Zeroizing::new([0u8; 32]);
    let argon2 = Argon2::default();

    argon2
        .hash_password_into(action_pass.as_bytes(), &salt, &mut *out_pass_ac)
        .map_err(|_| anyhow!("Couldn't hash the password using argon2"))?;

    let mut vec = Vec::new();
    vec.extend_from_slice(&salt);
    vec.extend_from_slice(&*out_pass_ac);

    let enc = BASE64_STANDARD.encode(vec);

    if enc == s {
        return Ok(());
    } else {
        return Err(anyhow!(
            "the action password didn't match try again with different one!"
        ));
    }
}

pub fn remove(id: &String, ef: Option<&String>) -> anyhow::Result<()> {
    let mut read_json = read_json(ef)?;

    println!(
        ">> are you sure you want to delete <{}>",
        id.bright_red().bold(),
    );
    print!(
        ">>[{}/{}]: ",
        "y".bright_cyan().bold(),
        "n".bright_red().bold()
    );
    stdout().flush()?;

    let mut str = String::new();
    stdin().read_line(&mut str)?;

    if str.trim() == "y" {
        if let Some(o) = read_json.iter().position(|s| s.id == *id) {
            read_json.remove(o);
        }

        let json = serde_json::to_string(&read_json)?;

        if let Some(ef) = ef {
            let enc_json = BASE64_STANDARD.encode(enc_all(json)?);
            fs::write(home_dirr()?.join(ef), &enc_json)?;
            #[cfg(unix)]
            set_perm_over_file(&home_dirr()?.join(ef))?;
        } else {
            let enc_json = BASE64_STANDARD.encode(enc_all(json)?);
            fs::write(home_dirr()?.join("obsidian/obs.json"), enc_json)?;
            #[cfg(unix)]
            set_perm_over_file(&home_dirr()?.join("obsidian/obs.json"))?;

            println!(
                ">>{} removed [{}]",
                "obsidian".bright_cyan().bold(),
                id.bright_white().bold()
            );
        }
    }
    Ok(())
}

#[cfg(unix)]
fn set_perm_over_file(path: &PathBuf) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let file = fs::File::open(path)?;
    let mut perm = file.metadata()?.permissions();
    perm.set_mode(0o600);

    fs::set_permissions(&path, perm)?;
    Ok(())
}

pub fn search(id: &String, ef: Option<&String>) -> anyhow::Result<()> {
    let read_json = read_json(ef)?;

    if let Some(ry) = read_json.iter().find(|u| u.id == *id) {
        println!(
            ">> {} [{}] [{}]",
            "found".bright_cyan().bold(),
            ry.id.to_string().bright_white().bold(),
            ry.data.to_string().bright_white().bold()
        );
    }
    Ok(())
}

pub fn change(
    id: &String,
    ef: Option<&String>,
    master_key: &String,
    password: &String,
    username_email: &String,
) -> anyhow::Result<()> {
    let password = Zeroizing::new(password.to_string());
    let master_key = Zeroizing::new(master_key.to_string());

    let mut read_json_i = read_json(ef)?;

    if let Some(o) = read_json_i
        .iter_mut()
        .find(|s| s.id == id.deref())
    {
        let enc = enc(&master_key, username_email, &password)?;
        let enc = BASE64_STANDARD.encode(enc);
        o.data = enc;
        let json = serde_json::to_string(&read_json_i)?;
        if let Some(ef) = ef {
            let enc_json = BASE64_STANDARD.encode(enc_all(json)?);
            fs::write(home_dirr()?.join(ef), &enc_json)?;
            #[cfg(unix)]
            set_perm_over_file(&home_dirr()?.join(ef))?;
        } else {
            let enc_json = BASE64_STANDARD.encode(enc_all(json)?);
            fs::write(
                home_dirr()?
                    .join("obsidian/obs.json")
                    .to_string_lossy()
                    .to_string(),
                &enc_json,
            )?;
            #[cfg(unix)]
            set_perm_over_file(&home_dirr()?.join("obsidian/obs.json"))?;
        }
    }
    Ok(())
}

pub fn generate_password() -> anyhow::Result<String> {
    use rand::distr::Alphanumeric;
    let gen_pass: String = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();
    println!(
        ">> {} <{}>",
        "generated password".bright_white().bold(),
        gen_pass.bright_yellow().bold()
    );
    Ok(gen_pass)
}

fn enc_all (data:String) -> anyhow::Result<Vec<u8>> { 
    let mut get_ac = fs::File::open(home_dirr()?.join("obsidian/obs_password.txt"))?;
    let mut storeit = String::new();
    get_ac.read_to_string(&mut storeit)?;

    let dec = BASE64_STANDARD.decode(&storeit.trim())?;
    let (_ , decc) = dec.split_at(16);

    let key = Key::<Aes256Gcm>::from_slice(&decc);
    let cip = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let data = cip.encrypt(&nonce, data.as_bytes()).map_err(|_| anyhow!("Couldn't enc vault"))?;

    let mut vec = Vec::new();
    vec.extend_from_slice(&nonce);
    vec.extend_from_slice(&data);

    return Ok(vec);
}

fn dec_all (data:Vec<u8>) -> anyhow::Result<Vec<u8>> {
    let mut get_ac = fs::File::open(home_dirr()?.join("obsidian/obs_password.txt"))?;
    let mut store_it = String::new();
    get_ac.read_to_string(&mut store_it)?;

    let dec = BASE64_STANDARD.decode(store_it)?;
    let (_ , decc) = dec.split_at(16);
    let (nonce , data) = data.split_at(12);

    let key = Key::<Aes256Gcm>::from_slice(&decc);
    let cip = Aes256Gcm::new(&key);
    let nonce = Nonce::from_slice(nonce);

    let data = cip.decrypt(&nonce, data).map_err(|_| anyhow!("Couldn't dec vault"))?;

    return Ok(data);
}