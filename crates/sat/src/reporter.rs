use crate::ui;
use anyhow::Result;

pub fn new_finding() -> Result<()> {
    ui::print_section_header("New Audit Finding");
    ui::print_notice("Launching interactive finding reporter...");
    ui::print_warning("Finding reporter is not yet implemented (Phase 6).");
    Ok(())
}
