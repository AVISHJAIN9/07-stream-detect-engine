use std::fmt;
use crate::rule_ast::ConditionExpr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    Ident(String),
    And,
    Or,
    Not,
    LParen,
    RParen,
    OneOf(String),
    AllOf(String),
}

#[derive(Debug, Clone)]
pub struct ParseConditionError {
    pub message: String,
    pub position: usize,
}

impl fmt::Display for ParseConditionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Condition parse error at position {}: {}", self.position, self.message)
    }
}

impl std::error::Error for ParseConditionError {}

pub struct ConditionLexer;

impl ConditionLexer {
    pub fn tokenize(input: &str) -> Result<Vec<Token>, ParseConditionError> {
        let mut tokens = Vec::new();
        let words: Vec<&str> = input.split_whitespace().collect();
        let mut i = 0;

        while i < words.len() {
            let word = words[i];

            // 1. Check for "1 of <pattern>" or "all of <pattern>"
            if (word == "1" || word == "all") && i + 2 < words.len() && words[i + 1] == "of" {
                let pattern = words[i + 2].trim_matches(|c| c == '(' || c == ')');
                if word == "1" {
                    tokens.push(Token::OneOf(pattern.to_string()));
                } else {
                    tokens.push(Token::AllOf(pattern.to_string()));
                }
                i += 3;
                continue;
            }

            // 2. Handle parentheses attached to words (e.g. "(selection1", "selection2)")
            let mut current = word;
            while current.starts_with('(') {
                tokens.push(Token::LParen);
                current = &current[1..];
            }

            let mut trailing_rparens = 0;
            while current.ends_with(')') {
                trailing_rparens += 1;
                current = &current[..current.len() - 1];
            }

            if !current.is_empty() {
                match current.to_lowercase().as_str() {
                    "and" => tokens.push(Token::And),
                    "or" => tokens.push(Token::Or),
                    "not" => tokens.push(Token::Not),
                    _ => tokens.push(Token::Ident(current.to_string())),
                }
            }

            for _ in 0..trailing_rparens {
                tokens.push(Token::RParen);
            }

            i += 1;
        }

        Ok(tokens)
    }
}

pub struct ConditionParser<'a> {
    tokens: &'a [Token],
    cursor: usize,
}

impl ConditionParser<'_> {
    pub fn parse(input: &str) -> Result<ConditionExpr, ParseConditionError> {
        let tokens = ConditionLexer::tokenize(input)?;
        Self::parse_tokens(&tokens)
    }

    pub fn parse_tokens(tokens: &[Token]) -> Result<ConditionExpr, ParseConditionError> {
        let mut parser = ConditionParser {
            tokens,
            cursor: 0,
        };
        let expr = parser.parse_or()?;
        if parser.cursor < parser.tokens.len() {
            return Err(ParseConditionError {
                message: format!("Unexpected trailing token: {:?}", parser.tokens[parser.cursor]),
                position: parser.cursor,
            });
        }
        Ok(expr)
    }
}

impl<'a> ConditionParser<'a> {

    // Precedence level 1 (lowest): OR
    fn parse_or(&mut self) -> Result<ConditionExpr, ParseConditionError> {
        let mut left = self.parse_and()?;

        while self.cursor < self.tokens.len() && self.tokens[self.cursor] == Token::Or {
            self.cursor += 1; // consume OR
            let right = self.parse_and()?;
            left = match left {
                ConditionExpr::Or(mut list) => {
                    list.push(right);
                    ConditionExpr::Or(list)
                }
                _ => ConditionExpr::Or(vec![left, right]),
            };
        }

        Ok(left)
    }

    // Precedence level 2: AND
    fn parse_and(&mut self) -> Result<ConditionExpr, ParseConditionError> {
        let mut left = self.parse_not()?;

        while self.cursor < self.tokens.len() && self.tokens[self.cursor] == Token::And {
            self.cursor += 1; // consume AND
            let right = self.parse_not()?;
            left = match left {
                ConditionExpr::And(mut list) => {
                    list.push(right);
                    ConditionExpr::And(list)
                }
                _ => ConditionExpr::And(vec![left, right]),
            };
        }

        Ok(left)
    }

    // Precedence level 3: NOT
    fn parse_not(&mut self) -> Result<ConditionExpr, ParseConditionError> {
        if self.cursor < self.tokens.len() && self.tokens[self.cursor] == Token::Not {
            self.cursor += 1; // consume NOT
            let operand = self.parse_not()?;
            Ok(ConditionExpr::Not(Box::new(operand)))
        } else {
            self.parse_primary()
        }
    }

    // Precedence level 4 (highest): primary expressions, parentheses, quantifiers
    fn parse_primary(&mut self) -> Result<ConditionExpr, ParseConditionError> {
        if self.cursor >= self.tokens.len() {
            return Err(ParseConditionError {
                message: "Unexpected end of condition expression".to_string(),
                position: self.cursor,
            });
        }

        match &self.tokens[self.cursor] {
            Token::Ident(name) => {
                let id = name.clone();
                self.cursor += 1;
                Ok(ConditionExpr::SearchRef(id))
            }
            Token::OneOf(pattern) => {
                let pat = pattern.clone();
                self.cursor += 1;
                Ok(ConditionExpr::OneOf(pat))
            }
            Token::AllOf(pattern) => {
                let pat = pattern.clone();
                self.cursor += 1;
                Ok(ConditionExpr::AllOf(pat))
            }
            Token::LParen => {
                self.cursor += 1; // consume '('
                let inner = self.parse_or()?;
                if self.cursor >= self.tokens.len() || self.tokens[self.cursor] != Token::RParen {
                    return Err(ParseConditionError {
                        message: "Expected closing ')'".to_string(),
                        position: self.cursor,
                    });
                }
                self.cursor += 1; // consume ')'
                Ok(inner)
            }
            other => Err(ParseConditionError {
                message: format!("Unexpected token in expression: {:?}", other),
                position: self.cursor,
            }),
        }
    }
}
