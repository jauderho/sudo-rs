use sudo_test::{Command, Env, TextFile, User};

use crate::{PASSWORD, USERNAME};

#[test]
fn can_retry_password() {
    let env = Env(format!("{USERNAME} ALL=(ALL:ALL) ALL"))
        .user(User(USERNAME).password(PASSWORD))
        .build();

    Command::new("sh")
        .arg("-c")
        .arg(format!(
            "(echo wrong-password; echo {PASSWORD}) | sudo -S true"
        ))
        .as_user(USERNAME)
        .output(&env)
        .assert_success();
}

#[test]
fn three_retries_allowed_by_default() {
    let env = Env(format!("{USERNAME} ALL=(ALL:ALL) ALL"))
        .user(User(USERNAME).password(PASSWORD))
        .build();

    let output = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "(for i in $(seq 1 3); do echo wrong-password; done; echo {PASSWORD}) | sudo -S true"
        ))
        .as_user(USERNAME)
        .output(&env);

    output.assert_exit_code(1);

    let stderr = output.stderr();

    let diagnostic = if sudo_test::is_original_sudo() {
        "3 incorrect password attempts"
    } else {
        "3 incorrect authentication attempts"
    };
    assert_contains!(output.stderr(), diagnostic);

    let password_prompt = if sudo_test::is_original_sudo() && cfg!(target_os = "linux") {
        "password for ferris:"
    } else {
        "Password:"
    };

    let num_password_prompts = stderr
        .lines()
        .filter(|line| line.contains(password_prompt))
        .count();

    assert_eq!(3, num_password_prompts);
}

#[test]
fn defaults_passwd_tries() {
    let env = Env(format!(
        "{USERNAME} ALL=(ALL:ALL) ALL
Defaults passwd_tries=2"
    ))
    .user(User(USERNAME).password(PASSWORD))
    .build();

    let output = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "(for i in $(seq 1 2); do echo wrong-password; done; echo {PASSWORD}) | sudo -S true"
        ))
        .as_user(USERNAME)
        .output(&env);

    output.assert_exit_code(1);

    let stderr = output.stderr();
    let diagnostic = if sudo_test::is_original_sudo() {
        "2 incorrect password attempts"
    } else {
        "2 incorrect authentication attempts"
    };
    assert_contains!(stderr, diagnostic);

    let password_prompt = if sudo_test::is_original_sudo() && cfg!(target_os = "linux") {
        "password for ferris:"
    } else {
        "Password:"
    };

    let num_password_prompts = stderr
        .lines()
        .filter(|line| line.contains(password_prompt))
        .count();

    assert_eq!(2, num_password_prompts);
}

// this is a PAM security feature
#[test]
#[cfg_attr(
    target_os = "freebsd",
    ignore = "on FreeBSD retry is immediately allowed"
)]
fn retry_is_not_allowed_immediately() {
    let script_path = "/tmp/script.sh";
    let env = Env(format!("{USERNAME} ALL=(ALL:ALL) ALL"))
        .file(
            script_path,
            TextFile(include_str!("password_retry/time-password-retry.sh")).chmod("777"),
        )
        .user(User(USERNAME).password(PASSWORD))
        .build();

    let delta_millis = time_password_retry(script_path, env);

    // by default, the retry delay should be around 2 seconds
    // use a lower value to avoid sporadic failures
    assert!(delta_millis >= 1250);
}

fn time_password_retry(script_path: &str, env: Env) -> u64 {
    let stdout = Command::new("sh")
        .arg(script_path)
        .as_user(USERNAME)
        .output(&env)
        .stdout();
    let timestamps = stdout
        .lines()
        .filter_map(|line| line.parse::<u64>().ok())
        .collect::<Vec<_>>();
    assert_eq!(2, timestamps.len());
    let delta_millis = timestamps[1] - timestamps[0];
    dbg!(delta_millis);
    delta_millis
}

#[test]
#[cfg_attr(
    target_os = "freebsd",
    ignore = "/etc/pam.d/common-auth doesn't exist on FreeBSD"
)]
fn can_control_retry_delay_using_pam() {
    const NEW_DELAY_MICROS: u32 = 5_000_000;

    let script_path = "/tmp/script.sh";
    let check_env = Env(format!("{USERNAME} ALL=(ALL:ALL) ALL"))
        .file(
            script_path,
            TextFile(include_str!("password_retry/time-password-retry.sh")).chmod("777"),
        )
        .user(User(USERNAME).password(PASSWORD))
        .build();
    let common_auth = Command::new("cat")
        .arg("/etc/pam.d/common-auth")
        .output(&check_env)
        .stdout();
    let common_auth = common_auth
        .lines()
        .filter(|line| !line.trim_start().starts_with('#') && !line.trim().is_empty())
        .collect::<Vec<&str>>()
        .join("\n");
    assert_eq!(
        "auth\t[success=1 default=ignore]\tpam_unix.so nullok
auth\trequisite\t\t\tpam_deny.so
auth\trequired\t\t\tpam_permit.so",
        common_auth,
        "the stock /etc/pam.d/common-auth file has changed; this test needs to be updated"
    );

    let initial_delta_millis = time_password_retry(script_path, check_env);

    // increase the retry delay from 2 seconds to 5
    let env = Env(format!("{USERNAME} ALL=(ALL:ALL) ALL"))
        .user(User(USERNAME).password(PASSWORD))
        .file(
            "/etc/pam.d/common-auth",
            format!(
                "auth optional pam_faildelay.so delay={NEW_DELAY_MICROS}
auth [success=1 default=ignore] pam_unix.so nullok nodelay
auth requisite pam_deny.so
auth required pam_permit.so"
            ),
        )
        .file(
            script_path,
            TextFile(include_str!("password_retry/time-password-retry.sh")).chmod("777"),
        )
        .build();

    let newer_delta_millis = time_password_retry(script_path, env);

    // use a lower value to avoid sporadic failures
    assert!(newer_delta_millis >= 3_100);

    assert!(
        newer_delta_millis > initial_delta_millis,
        "password retry delay appears to not have increased.
it could be that the image defaults to a high retry delay value; \
you may want to increase NEW_DELAY_MICROS"
    );
}
