use sudo_test::{Command, Env, TextFile};

use crate::Result;

#[test]
fn syslog_writer_should_not_hang() -> Result<()> {
    let env = Env(TextFile("ALL ALL=(ALL:ALL) NOPASSWD: ALL").chmod("644")).build()?;

    let stdout = Command::new("sudo")
        .args(["env", "CC=clang-18", "CXX=clang++-18", "FOO=\"........................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................\"", "whoami"])
        .output(&env)?
        .stdout()?;

    assert_eq!(stdout, "root");

    Ok(())
}
