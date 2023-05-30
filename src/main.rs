// Axel '0vercl0k' Souchet - May 25 2023
use clap::{Args, Parser, Subcommand};
use gflags::{Gflags, Result};

/// Subcommand for PageHeap related operations.
#[derive(Args)]
struct PageHeapOpts {
    /// Lists processes with GlobalFlags/PageHeapFlags.
    #[arg(long)]
    list: bool,

    /// Turns on page heap for a process.
    #[arg(long, value_name = "process name")]
    add: Option<String>,

    /// Removes page heap off a process.
    #[arg(long, value_name = "process name")]
    del: Option<String>,
}

/// Subcommand for Debugger related operations.
#[derive(Args)]
struct DebuggerOpts {
    /// Lists processes that starts with a Debugger.
    #[arg(long)]
    list: bool,

    /// Adds a Debugger for a specific process.
    #[arg(long, value_name = "process name")]
    add: Option<String>,

    /// Adds a Debugger for a specific process.
    #[arg(long, value_name = "debugger path")]
    dbg: Option<String>,

    /// Removes a Debugger for a specific process.
    #[arg(long, value_name = "process name")]
    del: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    Ph(PageHeapOpts),
    Dbg(DebuggerOpts),
}

/// Command-line arguments.
#[derive(Parser)]
#[command(about = "A simple tool to turn on/off PageHeap on Windows processes")]
struct Opts {
    /// PageHeap related options.
    #[command(subcommand)]
    commands: Commands,
}

/// Takes care of the PageHeap options.
fn pageheap_subcommand(gflags: &Gflags, opts: &PageHeapOpts) -> Result<()> {
    if opts.list {
        println!("Processes that have PageHeap enabled:");
        for name in gflags.list_pageheap()? {
            println!("  - {name}");
        }
    }

    if let Some(ref process_name) = opts.add {
        match gflags.add_pageheap(process_name)? {
            true => println!("Successfully enabled PageHeap for {process_name}"),
            false => println!("PageHeap was already enabled for {process_name}"),
        }
    }

    if let Some(ref process_name) = opts.del {
        match gflags.remove_pageheap(process_name)? {
            true => println!("Successfully removed PageHeap for {process_name}"),
            false => println!("PageHeap is not enabled for {process_name}"),
        }
    }

    Ok(())
}

/// Takes care of the Debugger options.
fn dbg_subcommand(gflags: &Gflags, opts: &DebuggerOpts) -> Result<()> {
    if opts.list {
        println!("Processes that have a Debugger enabled:");
        for (name, dbg) in gflags.list_debugger()? {
            println!("  - {name}: {dbg}");
        }
    }

    if let Some(ref process_name) = opts.add {
        let debugger = opts
            .dbg
            .as_ref()
            .unwrap_or_else(|| panic!("Need to pass a --debugger path!"));

        match gflags.add_debugger(process_name, debugger)? {
            (true, debugger) => {
                println!("Successfully added \"{debugger}\" as a debugger for {process_name}")
            }
            (false, debugger) => println!(
                "\"{debugger}\" is already defined for {process_name} (use --del to override it)"
            ),
        }
    }

    if let Some(ref process_name) = opts.del {
        match gflags.remove_pageheap(process_name)? {
            true => println!("Successfully removed PageHeap for {process_name}"),
            false => println!("PageHeap is not enabled for {process_name}"),
        }
    }

    Ok(())
}

fn main() -> Result<()> {
    let opts = Opts::parse();
    let gflags = Gflags::new()?;

    match opts.commands {
        Commands::Ph(ref pageheap_opts) => pageheap_subcommand(&gflags, pageheap_opts),
        Commands::Dbg(ref dbg_opts) => dbg_subcommand(&gflags, dbg_opts),
    }
}
