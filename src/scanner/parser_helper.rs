use anyhow::Result;
use std::cell::RefCell;

use crate::parser::LanguageParser;

thread_local! {
    static TLS_PARSER: RefCell<Option<(String, LanguageParser)>> = const { RefCell::new(None) };
}

pub(crate) fn with_local_parser<F, R>(language: &str, f: F) -> Result<R>
where
    F: FnOnce(&mut LanguageParser) -> Result<R>,
{
    TLS_PARSER.try_with(|cell| {
        let mut opt = cell.borrow_mut();
        match *opt {
            Some((ref lang, ref mut parser)) if lang == language => f(parser),
            _ => {
                let mut parser = LanguageParser::new(language)?;
                let result = f(&mut parser)?;
                *opt = Some((language.to_string(), parser));
                Ok(result)
            }
        }
    })?
}
