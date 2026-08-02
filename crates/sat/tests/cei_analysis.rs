use sat::analyzer;
use sat::types::{Finding, Severity};

/// Runs the analyzer on `source` and returns only the CEI findings.
fn cei_findings(source: &str) -> Vec<Finding> {
    let (_accounts, _instructions, findings) = analyzer::analyze_string_for_test(source);
    findings.into_iter().filter(|f| f.title.contains("CEI Violation")).collect()
}

#[test]
fn test_cei_write_after_cpi_inside_if_body_flagged() {
    let source = r#"
#[program]
pub mod my_program {
    use super::*;

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        if amount > 0 {
            invoke(&instruction, &[ctx.accounts.vault.to_account_info()])?;
            ctx.accounts.vault.balance -= amount;
        }
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
    pub external_program: AccountInfo<'info>,
}

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
}
"#;

    let findings = cei_findings(source);
    assert_eq!(findings.len(), 1, "write after invoke() inside an if body should be flagged once");
    assert_eq!(findings[0].severity, Severity::Critical);
    assert!(findings[0].description.contains("reentrancy"));
}

#[test]
fn test_cei_write_after_cpi_inside_match_arm_flagged() {
    let source = r#"
#[program]
pub mod my_program {
    use super::*;

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64, action: u8) -> Result<()> {
        match action {
            1 => {
                invoke(&instruction, &[ctx.accounts.vault.to_account_info()])?;
                ctx.accounts.vault.balance -= amount;
            }
            _ => {}
        }
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
    pub external_program: AccountInfo<'info>,
}

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
}
"#;

    let findings = cei_findings(source);
    assert_eq!(findings.len(), 1, "write after invoke() inside a match arm should be flagged once");
    assert_eq!(findings[0].severity, Severity::Critical);
}

#[test]
fn test_cei_write_after_cpi_inside_for_loop_body_flagged() {
    let source = r#"
#[program]
pub mod my_program {
    use super::*;

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        for _ in 0..amount {
            invoke(&instruction, &[ctx.accounts.vault.to_account_info()])?;
            ctx.accounts.vault.balance -= 1;
        }
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
    pub external_program: AccountInfo<'info>,
}

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
}
"#;

    let findings = cei_findings(source);
    assert_eq!(findings.len(), 1, "write after invoke() inside a for loop body should be flagged once");
    assert_eq!(findings[0].severity, Severity::Critical);
}

#[test]
fn test_cei_cpi_in_then_branch_does_not_flag_else_or_following_writes() {
    let source = r#"
#[program]
pub mod my_program {
    use super::*;

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        if amount > 0 {
            invoke(&instruction, &[ctx.accounts.vault.to_account_info()])?;
        } else {
            ctx.accounts.vault.balance -= amount;
        }
        ctx.accounts.vault.balance += 1;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
    pub external_program: AccountInfo<'info>,
}

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
}
"#;

    let findings = cei_findings(source);
    assert!(findings.is_empty(), "a CPI in the then-branch must not flag writes in the else branch or after the if");
}

#[test]
fn test_cei_write_before_cpi_not_flagged() {
    let source = r#"
#[program]
pub mod my_program {
    use super::*;

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        ctx.accounts.vault.balance -= amount;
        invoke(&instruction, &[ctx.accounts.vault.to_account_info()])?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
    pub external_program: AccountInfo<'info>,
}

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
}
"#;

    let findings = cei_findings(source);
    assert!(findings.is_empty(), "write BEFORE the CPI is safe and must not be flagged");
}

#[test]
fn test_cei_top_level_write_after_top_level_cpi_flagged() {
    let source = r#"
#[program]
pub mod my_program {
    use super::*;

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        invoke(&instruction, &[ctx.accounts.vault.to_account_info()])?;
        ctx.accounts.vault.balance -= amount;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
    pub external_program: AccountInfo<'info>,
}

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
}
"#;

    let findings = cei_findings(source);
    assert_eq!(findings.len(), 1, "top-level write after top-level invoke() should be flagged once");
    assert_eq!(findings[0].severity, Severity::Critical);
}

#[test]
fn test_cei_write_in_loop_body_after_top_level_cpi_flagged() {
    let source = r#"
#[program]
pub mod my_program {
    use super::*;

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        invoke(&instruction, &[ctx.accounts.vault.to_account_info()])?;
        for _ in 0..amount {
            ctx.accounts.vault.balance -= 1;
        }
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
    pub external_program: AccountInfo<'info>,
}

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
}
"#;

    let findings = cei_findings(source);
    assert_eq!(findings.len(), 1, "a CPI before the loop conservatively flags writes inside the loop body");
}

#[test]
fn test_cei_cpi_in_one_match_arm_does_not_flag_another_arm() {
    let source = r#"
#[program]
pub mod my_program {
    use super::*;

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64, action: u8) -> Result<()> {
        match action {
            1 => {
                invoke(&instruction, &[ctx.accounts.vault.to_account_info()])?;
            }
            _ => {
                ctx.accounts.vault.balance -= amount;
            }
        }
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
    pub external_program: AccountInfo<'info>,
}

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
}
"#;

    let findings = cei_findings(source);
    assert!(findings.is_empty(), "a CPI in one match arm must not flag writes in a sibling arm (branch isolation)");
}

#[test]
fn test_cei_no_cpi_no_findings() {
    let source = r#"
#[program]
pub mod my_program {
    use super::*;

    pub fn update(ctx: Context<Update>, value: u64) -> Result<()> {
        ctx.accounts.state.value = value;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Update<'info> {
    #[account(mut)]
    pub state: Account<'info, State>,
    pub authority: Signer<'info>,
}

#[account]
pub struct State {
    pub authority: Pubkey,
    pub value: u64,
}
"#;

    let findings = cei_findings(source);
    assert!(findings.is_empty(), "no CPI calls — should have no CEI findings");
}
