//! Various tokens

use super::basic_parser::{Many, Token};

#[cfg_attr(test, derive(Clone, PartialEq, Eq))]
pub struct Username(pub String);

/// A username consists of alphanumeric characters as well as "." and "-", but does not start with an underscore.
impl Token for Username {
    fn construct(text: String) -> Result<Self, String> {
        Ok(Username(text))
    }

    fn accept(c: char) -> bool {
        c.is_ascii_alphanumeric() || ".-_".contains(c)
    }

    fn accept_1st(c: char) -> bool {
        c != '_' && Self::accept(c)
    }
}

impl Many for Username {}

pub struct Digits(pub u32);

impl Token for Digits {
    const MAX_LEN: usize = 9;

    fn construct(s: String) -> Result<Self, String> {
        Ok(Digits(s.parse().unwrap()))
    }

    fn accept(c: char) -> bool {
        c.is_ascii_digit()
    }
}

pub struct Numeric(pub String);

impl Token for Numeric {
    const MAX_LEN: usize = 38;

    fn construct(s: String) -> Result<Self, String> {
        Ok(Numeric(s))
    }

    fn accept(c: char) -> bool {
        c.is_ascii_hexdigit()
    }
}

/// A hostname consists of alphanumeric characters and ".", "-",  "_"
pub struct Hostname(pub String);

impl std::ops::Deref for Hostname {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Token for Hostname {
    fn construct(text: String) -> Result<Self, String> {
        Ok(Hostname(text))
    }

    fn accept(c: char) -> bool {
        c.is_ascii_alphanumeric() || ".-_".contains(c)
    }
}

impl Many for Hostname {}

/// This enum allows items to use the ALL wildcard or be specified with aliases, or directly.
/// (Maybe this is better defined not as a Token but simply directly as an implementation of [crate::sudoers::basic_parser::Parse])
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub enum Meta<T> {
    All,
    Only(T),
    Alias(String),
}

impl<T: Token> Token for Meta<T> {
    fn construct(s: String) -> Result<Self, String> {
        Ok(if s == "ALL" {
            Meta::All
        } else if s.starts_with(AliasName::accept_1st) && s.chars().skip(1).all(AliasName::accept) {
            Meta::Alias(s)
        } else {
            Meta::Only(T::construct(s)?)
        })
    }

    const MAX_LEN: usize = T::MAX_LEN;

    fn accept(c: char) -> bool {
        T::accept(c) || c.is_uppercase()
    }
    fn accept_1st(c: char) -> bool {
        T::accept_1st(c) || c.is_uppercase()
    }

    const ESCAPE: char = T::ESCAPE;

    fn escaped(c: char) -> bool {
        T::escaped(c)
    }
}

impl<T: Many> Many for Meta<T> {
    const SEP: char = T::SEP;
    const LIMIT: usize = T::LIMIT;
}

/// An identifier that consits of only uppercase characters.
pub struct AliasName(pub String);

impl Token for AliasName {
    fn construct(s: String) -> Result<Self, String> {
        Ok(AliasName(s))
    }

    fn accept_1st(c: char) -> bool {
        c.is_ascii_uppercase() || c.is_ascii_digit()
    }

    fn accept(c: char) -> bool {
        Self::accept_1st(c) || c == '_'
    }
}

/// A struct that represents valid command strings; this can contain escape sequences and are
/// limited to 1024 characters.
pub type Command = (glob::Pattern, Option<Box<[String]>>);

impl Token for Command {
    const MAX_LEN: usize = 1024;

    fn construct(s: String) -> Result<Self, String> {
        let cvt_err = |pat: Result<_, glob::PatternError>| {
            pat.map_err(|err| format!("wildcard pattern error {err}"))
        };

        // the tokenizer should not give us a token that consists of only whitespace
        let mut cmd_iter = s.split_whitespace();
        let cmd = cmd_iter.next().unwrap();
        let mut args = cmd_iter.map(String::from).collect::<Vec<String>>();

        let argpat = if args.is_empty() {
            // if no arguments are mentioned, anything is allowed
            None
        } else {
            if args.last().map(|x| -> &str { x }) == Some("\"\"") {
                // if the magic "" appears, no (further) arguments are allowed
                args.pop();
            }
            Some(args.into_boxed_slice())
        };

        Ok((cvt_err(glob::Pattern::new(cmd))?, argpat))
    }

    // all commands start with "/" except "sudoedit"
    fn accept_1st(c: char) -> bool {
        c == '/' || c == 's'
    }

    fn accept(c: char) -> bool {
        !Self::escaped(c) && !c.is_control()
    }

    const ESCAPE: char = '\\';
    fn escaped(c: char) -> bool {
        "\\,:=#".contains(c)
    }
}

impl Many for Command {}

/// An environment variable name pattern consists of alphanumeric characters as well as "_", "%" and wildcard "*"
/// (Value patterns are not supported yet)
pub struct EnvVar(pub String);

impl Token for EnvVar {
    fn construct(text: String) -> Result<Self, String> {
        Ok(EnvVar(text))
    }

    fn accept(c: char) -> bool {
        c.is_ascii_alphanumeric() || "*_%".contains(c)
    }
}

pub struct QuotedText(pub String);

impl Token for QuotedText {
    const MAX_LEN: usize = 1024;

    fn construct(s: String) -> Result<Self, String> {
        Ok(QuotedText(s))
    }

    fn accept(c: char) -> bool {
        !Self::escaped(c)
    }

    const ESCAPE: char = '\\';
    fn escaped(c: char) -> bool {
        "\\\"".contains(c) || c.is_control()
    }
}

pub struct IncludePath(pub String);

impl Token for IncludePath {
    const MAX_LEN: usize = 1024;

    fn construct(s: String) -> Result<Self, String> {
        Ok(IncludePath(s))
    }

    fn accept(c: char) -> bool {
        !c.is_control() && !Self::escaped(c)
    }

    const ESCAPE: char = '\\';
    fn escaped(c: char) -> bool {
        "\\\" ".contains(c)
    }
}

// used for Defaults where quotes around some items are optional
pub struct StringParameter(pub String);

impl Token for StringParameter {
    const MAX_LEN: usize = QuotedText::MAX_LEN;

    fn construct(s: String) -> Result<Self, String> {
        Ok(StringParameter(s))
    }

    fn accept(c: char) -> bool {
        !c.is_control() && !Self::escaped(c)
    }

    const ESCAPE: char = '\\';
    fn escaped(c: char) -> bool {
        "\\\" #,".contains(c)
    }
}

// a path used for in CWD and CHROOT specs
#[derive(Clone)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub enum ChDir {
    Path(std::path::PathBuf),
    Any,
}

impl Token for ChDir {
    const MAX_LEN: usize = 1024;

    fn construct(s: String) -> Result<Self, String> {
        if s == "*" {
            Ok(ChDir::Any)
        } else if s.contains('*') {
            Err("path cannot contain '*'".to_string())
        } else {
            Ok(ChDir::Path(s.into()))
        }
    }

    fn accept(c: char) -> bool {
        !c.is_control() && !Self::escaped(c)
    }

    fn accept_1st(c: char) -> bool {
        "~/*".contains(c)
    }

    const ESCAPE: char = '\\';
    fn escaped(c: char) -> bool {
        "\\\" ".contains(c)
    }
}