//! Python inline frontend. A deliberately small Unix CLI over a resident Ghidra service.
use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::TcpStream;

#[derive(Parser)]
#[command(
    name = "ghidra",
    version,
    about = "Resident Ghidra, Python inline, ordinary shell output"
)]
struct Cli {
    #[arg(long, global = true)]
    target: Option<String>,
    #[arg(
        long,
        env = "GHIDRA_CLI_SERVER",
        default_value = "127.0.0.1:8089",
        global = true
    )]
    server: String,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Open an existing project/program and print its immutable target ID.
    Use {
        #[arg(long)]
        project: String,
        #[arg(long)]
        program: String,
    },
    /// Execute Python from standard input. stdout is only your script's output.
    Exec {
        #[arg(long)]
        write: bool,
        /// Values exposed as Python args (after --).
        #[arg(last = true)]
        args: Vec<String>,
    },
    /// One job per TSV line: job, state, target, mode, blockers.
    Jobs { job: Option<String> },
    /// Request cooperative cancellation of one job.
    Cancel { job: String },
}
fn call(server: &str, request: &Value, mut consume: impl FnMut(Value) -> Result<()>) -> Result<()> {
    let server = server.trim_start_matches("http://").trim_end_matches('/');
    let body = serde_json::to_vec(request)?;
    let mut stream = TcpStream::connect(server).with_context(|| format!("Connect to {server}"))?;
    stream.set_nodelay(true)?;
    write!(stream, "POST /call HTTP/1.0\r\nHost: {server}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n", body.len())?;
    stream.write_all(&body)?;
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    if !line.contains("200") {
        return Err(anyhow!("HTTP response: {}", line.trim()));
    }
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            return Err(anyhow!("Incomplete HTTP response"));
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
    }
    let mut received = false;
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        if !line.trim().is_empty() {
            consume(serde_json::from_str(&line)?)?;
            received = true;
        }
    }
    if !received {
        return Err(anyhow!("Server returned no execution result"));
    }
    Ok(())
}
fn report(detail: &Value) -> Result<()> {
    let mut file = tempfile::Builder::new()
        .prefix("ghidra-cli-error-")
        .suffix(".txt")
        .tempfile()?;
    // This is a readable diagnostic file, not a JSON CLI output mode.
    if let Some(object) = detail.as_object() {
        for (key, value) in object {
            if let Some(text) = value.as_str() {
                writeln!(file, "{key}:\n{text}\n")?;
            } else {
                writeln!(file, "{key}: {value}\n")?;
            }
        }
    }
    let (_, path) = file.keep()?;
    eprintln!("{}", path.display());
    Ok(())
}
fn run(cli: Cli) -> Result<bool> {
    let mut request = match &cli.command {
        Command::Use { project, program } => {
            json!({"command":"use", "project":project,"program":program})
        }
        Command::Exec { write, args } => {
            let mut code = String::new();
            io::stdin().read_to_string(&mut code)?;
            let sha = format!("{:x}", Sha256::digest(code.as_bytes()));
            json!({"command":"exec","code":code,"sha256":sha,"write":write,"args":args})
        }
        Command::Jobs { job } => json!({"command":"jobs","job":job}),
        Command::Cancel { job } => json!({"command":"cancel","job":job}),
    };
    if !matches!(cli.command, Command::Use { .. }) {
        match cli.target {
            Some(ref target) => request["target"] = json!(target),
            None => {
                report(
                    &json!({"code":"TARGET_REQUIRED","next_action":"use --project ... --program ..., then specify --target"}),
                )?;
                return Ok(false);
            }
        }
    }
    let mut success = true;
    let mut terminal = !matches!(cli.command, Command::Exec { .. });
    let mut job_id = None;
    let result = call(&cli.server, &request, |event| {
        match event["event"].as_str().unwrap_or("") {
            "stdout" => {
                io::stdout().write_all(event["text"].as_str().unwrap_or("").as_bytes())?;
                io::stdout().flush()?;
            }
            "stderr" => {
                io::stderr().write_all(event["text"].as_str().unwrap_or("").as_bytes())?;
                io::stderr().flush()?;
            }
            "job" => job_id = event["job"].as_str().map(str::to_owned),
            "error" => {
                report(&event["detail"])?;
                success = false;
                terminal = true;
            }
            "done" => {
                terminal = true;
                success &= event["status"] == "success";
            }
            "result" => {
                let value = &event["data"];
                if let Some(text) = value.as_str() {
                    writeln!(io::stdout(), "{text}")?;
                } else {
                    let items = if let Some(items) = value.as_array() {
                        items.clone()
                    } else {
                        vec![value.clone()]
                    };
                    for item in items {
                        let text = |key: &str| {
                            item[key].as_str().unwrap_or("-").replace(['\n', '\t'], " ")
                        };
                        let blocked = item["blocked_by"]
                            .as_array()
                            .map(|v| {
                                v.iter()
                                    .filter_map(Value::as_str)
                                    .collect::<Vec<_>>()
                                    .join(",")
                            })
                            .unwrap_or_default();
                        writeln!(
                            io::stdout(),
                            "{}\t{}\t{}\t{}\t{}",
                            text("id"),
                            text("state"),
                            text("target"),
                            if item["write"] == true {
                                "write"
                            } else {
                                "read"
                            },
                            blocked
                        )?;
                    }
                }
            }
            _ => {}
        }
        Ok(())
    });
    if let Err(error) = result {
        // Disconnecting the stream requests cooperative cancellation at the server.
        if error
            .downcast_ref::<io::Error>()
            .is_some_and(|e| e.kind() == io::ErrorKind::BrokenPipe)
        {
            if !terminal {
                eprintln!(
                    "CANCEL_REQUESTED: output pipe closed; cancellation requested for job {}",
                    job_id.as_deref().unwrap_or("unknown")
                );
            } else {
                eprintln!("BROKEN_PIPE: output pipe closed");
            }
            return Ok(false);
        }
        report(
            &json!({"code":"CONNECTION_ERROR","message":format!("{error:#}"),"job":job_id,"target":request["target"],"next_action":"check jobs before retrying a write"}),
        )?;
        return Ok(false);
    }
    if !terminal {
        report(
            &json!({"code":"EXECUTION_INTERRUPTED","job":job_id,"next_action":"check jobs; the stream ended without a completion response"}),
        )?;
        return Ok(false);
    }
    Ok(success)
}
fn main() {
    // Python/Java workers keep stdout pure; this frontend only formats transport events.
    let code = match run(Cli::parse()) {
        Ok(true) => 0,
        Ok(false) => 1,
        Err(error) => {
            if report(&json!({"code":"CLI_ERROR","message":format!("{error:#}")})).is_err() {
                eprintln!("Could not save error detail: {error:#}");
            }
            1
        }
    };
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;
    #[test]
    fn cli_is_consistent() {
        Cli::command().debug_assert();
    }
    #[test]
    fn parse_inline_and_target() {
        let cli = Cli::try_parse_from(["ghidra", "--target", "T1", "exec", "--write", "--", "arg"])
            .unwrap();
        assert_eq!(cli.target.as_deref(), Some("T1"));
        assert!(matches!(cli.command, Command::Exec { write: true, .. }));
    }
}
