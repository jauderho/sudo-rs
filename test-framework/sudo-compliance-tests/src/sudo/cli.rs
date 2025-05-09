use sudo_test::{Command, Env};

use crate::{Result, SUDOERS_ALL_ALL_NOPASSWD};

macro_rules! assert_snapshot {
    ($($tt:tt)*) => {
        insta::with_settings!({
            prepend_module_to_snapshot => false,
            snapshot_path => "../snapshots/secure_path",
        }, {
            insta::assert_snapshot!($($tt)*)
        });
    };
}

#[test]
fn just_dash_dash_works() {
    let env = Env(SUDOERS_ALL_ALL_NOPASSWD).build();

    Command::new("sudo")
        .args(["--", "true"])
        .output(&env)
        .assert_success();
}

#[test]
fn dash_dash_after_other_flag_works() {
    let env = Env(SUDOERS_ALL_ALL_NOPASSWD).build();

    Command::new("sudo")
        .args(["-u", "root", "--", "true"])
        .output(&env)
        .assert_success();
}

#[test]
fn dash_dash_before_flag_is_an_error() {
    let env = Env(SUDOERS_ALL_ALL_NOPASSWD).build();

    let output = Command::new("sudo")
        .args(["--", "-u", "root", "true"])
        .output(&env);

    output.assert_exit_code(1);

    let stderr = output.stderr();
    if sudo_test::is_original_sudo() {
        assert_snapshot!(stderr);
    } else {
        assert_contains!(stderr, "'-u': command not found");
    }
}

#[test]
fn dash_flag_space_value_syntax() -> Result<()> {
    let expected = 0;
    let env = Env(SUDOERS_ALL_ALL_NOPASSWD).build();

    let actual = Command::new("sudo")
        .args(["-u", "root", "id", "-u"])
        .output(&env)
        .stdout()
        .parse::<u16>()?;

    assert_eq!(expected, actual);

    Ok(())
}

#[test]
fn dash_flag_no_space_value_syntax() -> Result<()> {
    let expected = 0;
    let env = Env(SUDOERS_ALL_ALL_NOPASSWD).build();

    let actual = Command::new("sudo")
        .args(["-uroot", "id", "-u"])
        .output(&env)
        .stdout()
        .parse::<u16>()?;

    assert_eq!(expected, actual);

    Ok(())
}

#[test]
fn dash_flag_equal_value_invalid_syntax() {
    let env = Env(SUDOERS_ALL_ALL_NOPASSWD).build();

    let output = Command::new("sudo")
        .args(["-u=root", "id", "-u"])
        .output(&env);

    output.assert_exit_code(1);

    let diagnostic = if sudo_test::is_original_sudo() {
        "sudo: unknown user =root"
    } else {
        "invalid option"
    };
    assert_contains!(output.stderr(), diagnostic);
}

#[test]
fn dash_dash_flag_space_value_syntax() -> Result<()> {
    let expected = 0;
    let env = Env(SUDOERS_ALL_ALL_NOPASSWD).build();

    let actual = Command::new("sudo")
        .args(["--user", "root", "id", "-u"])
        .output(&env)
        .stdout()
        .parse::<u16>()?;

    assert_eq!(expected, actual);

    Ok(())
}

#[test]
fn dash_dash_flag_equal_value_syntax() -> Result<()> {
    let expected = 0;
    let env = Env(SUDOERS_ALL_ALL_NOPASSWD).build();

    let actual = Command::new("sudo")
        .args(["--user=root", "id", "-u"])
        .output(&env)
        .stdout()
        .parse::<u16>()?;

    assert_eq!(expected, actual);

    Ok(())
}

#[test]
fn lax_validation() {
    let env = Env(SUDOERS_ALL_ALL_NOPASSWD).build();
    let output = Command::new("sudo")
        .args(["--remove-timestamp", "-u", "root"])
        .output(&env);

    output.assert_exit_code(1);

    assert_contains!(output.stderr(), "usage");
}

#[test]
fn miscategorized_reset_timestamp_action() {
    let env = Env(SUDOERS_ALL_ALL_NOPASSWD).build();
    let output = Command::new("env")
        .args([
            "SHELL=/usr/bin/false",
            "sudo",
            "--reset-timestamp",
            "--shell",
        ])
        .output(&env);

    output.assert_exit_code(1);
}
