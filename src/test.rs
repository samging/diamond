#[cfg(test)]
mod test {
    use crate::{backend::safe::PasswordChecker, dec_enc::generate_password};

    #[test]
    fn _test() -> anyhow::Result<()> {
        Ok(())
    }
    #[test]
    fn _test_() -> anyhow::Result<()> {
        "gym2008m$mohammed"
            .to_string()
            .check_password_(&"".to_string(), Ok("mohammed".to_string()).as_ref())?;
        Ok(())
    }
    #[test]
    fn __test__() -> anyhow::Result<()> {
        let gp = generate_password()?;
        gp.check_password_(&"".to_string(), Ok("mohammed".to_string()).as_ref())?;
        Ok(())
    }
}
