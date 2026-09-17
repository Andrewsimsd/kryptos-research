//! Command parsing and filesystem/terminal adapters for the pure library.

use std::{error::Error, ffi::OsString, fs, io::Write, path::PathBuf};

use kryptos_research::feasibility::batch;
use kryptos_research::primers::filter_decimal_primers;
use kryptos_research::statistics::width_scan::{ScanRequest, scan};
use kryptos_research::statistics::{SimulationRequest, StatisticModel, simulate};
use kryptos_research::{diagnosis::diagnose, evidence::Evidence, transforms::execute_batch};

const HELP: &str = "Usage: kryptos-research <validate|diagnose> [EVIDENCE.json]\n\
    \x20      kryptos-research transform REQUESTS.json\n\
    \x20      kryptos-research primers [EVIDENCE.json]\n\
    \x20      kryptos-research statistics REQUEST.json\n\
    \x20      kryptos-research width-scan REQUEST.json\n\
    \x20      kryptos-research feasibility REQUEST.json\n\
    \n\
    validate  Check the 97-letter manifest, line layout, sources, and anchors.\n\
    diagnose  Emit JSON necessary-condition checks and contradiction witnesses.\n\
    transform Execute explicit cipher pipelines and emit JSON position traces.\n\
    primers   Filter all 99,999 nonzero decimal five-digit Gromark primers.\n\
    statistics Simulate five fixed statistics using evidence/k4.json and an explicit seed.\n\
    width-scan Calibrate and evaluate a maximum-statistic scan over widths 1-48.\n\
    feasibility Find complete alphabet witnesses for explicitly supplied primers.\n\
    \n\
    EVIDENCE.json defaults to evidence/k4.json relative to the current directory.\n\
    Inputs are strict uppercase ASCII; no implicit normalization is performed.\n\
    Diagnostics cover aligned baseline models only and do not recover plaintext.\n";

#[derive(Debug, PartialEq, Eq)]
enum Command {
    Help,
    Validate(PathBuf),
    Diagnose(PathBuf),
    Transform(PathBuf),
    Primers(PathBuf),
    Statistics(PathBuf),
    WidthScan(PathBuf),
    Feasibility(PathBuf),
}

fn parse(arguments: impl IntoIterator<Item = OsString>) -> Result<Command, &'static str> {
    let mut arguments = arguments.into_iter();
    let command = arguments.next();
    let command = match command.as_ref().and_then(|value| value.to_str()) {
        Some("--help" | "-h") => "help",
        Some("validate") => "validate",
        Some("diagnose") => "diagnose",
        Some("transform") => "transform",
        Some("primers") => "primers",
        Some("statistics") => "statistics",
        Some("width-scan") => "width-scan",
        Some("feasibility") => "feasibility",
        _ => {
            return Err(
                "expected validate, diagnose, transform, primers, statistics, width-scan or feasibility; use --help for usage",
            );
        }
    };
    if command == "help" {
        return if arguments.next().is_none() {
            Ok(Command::Help)
        } else {
            Err("--help takes no additional arguments")
        };
    }
    let supplied_path = arguments.next();
    if matches!(
        command,
        "transform" | "statistics" | "width-scan" | "feasibility"
    ) && supplied_path.is_none()
    {
        return Err("command requires a JSON request file; use --help for usage");
    }
    let path = supplied_path.map_or_else(|| PathBuf::from("evidence/k4.json"), PathBuf::from);
    if arguments.next().is_some() {
        return Err("expected at most one evidence file; use --help for usage");
    }
    Ok(if command == "validate" {
        Command::Validate(path)
    } else if command == "diagnose" {
        Command::Diagnose(path)
    } else if command == "primers" {
        Command::Primers(path)
    } else if command == "statistics" {
        Command::Statistics(path)
    } else if command == "width-scan" {
        Command::WidthScan(path)
    } else if command == "feasibility" {
        Command::Feasibility(path)
    } else {
        Command::Transform(path)
    })
}

pub(crate) fn run(
    arguments: impl IntoIterator<Item = OsString>,
    output: &mut impl Write,
) -> Result<(), Box<dyn Error>> {
    let command = parse(arguments)?;
    let path = match &command {
        Command::Help => return Ok(output.write_all(HELP.as_bytes())?),
        Command::Validate(path)
        | Command::Diagnose(path)
        | Command::Transform(path)
        | Command::Statistics(path)
        | Command::WidthScan(path)
        | Command::Feasibility(path)
        | Command::Primers(path) => path,
    };
    let text = fs::read_to_string(path).map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!("cannot read {}: {error}", path.display()),
        )
    })?;
    if matches!(command, Command::Transform(_)) {
        serde_json::to_writer_pretty(&mut *output, &execute_batch(&text)?)?;
        writeln!(output)?;
        return Ok(());
    }
    if matches!(command, Command::Statistics(_)) {
        let request: SimulationRequest = serde_json::from_str(&text)?;
        let evidence = Evidence::from_json(&fs::read_to_string("evidence/k4.json")?)?;
        serde_json::to_writer_pretty(
            &mut *output,
            &simulate(&StatisticModel::new(&evidence), request)?,
        )?;
        writeln!(output)?;
        return Ok(());
    }
    if matches!(command, Command::WidthScan(_)) {
        let request: ScanRequest = serde_json::from_str(&text)?;
        let evidence = Evidence::from_json(&fs::read_to_string("evidence/k4.json")?)?;
        serde_json::to_writer_pretty(&mut *output, &scan(&evidence, request)?)?;
        writeln!(output)?;
        return Ok(());
    }
    if matches!(command, Command::Feasibility(_)) {
        let request: batch::Request = serde_json::from_str(&text)?;
        let evidence = Evidence::from_json(&fs::read_to_string("evidence/k4.json")?)?;
        serde_json::to_writer_pretty(&mut *output, &batch::evaluate(&evidence, &request)?)?;
        writeln!(output)?;
        return Ok(());
    }
    let evidence = Evidence::from_json(&text)?;
    match command {
        Command::Validate(_) => writeln!(
            output,
            "{}: valid; {} ciphertext letters, {} known plaintext letters",
            evidence.id(),
            evidence.ciphertext().len(),
            evidence.known_letters().count()
        )?,
        Command::Diagnose(_) => {
            serde_json::to_writer_pretty(&mut *output, &diagnose(&evidence))?;
            writeln!(output)?;
        }
        Command::Primers(_) => {
            serde_json::to_writer_pretty(&mut *output, &filter_decimal_primers(&evidence)?)?;
            writeln!(output)?;
        }
        Command::Help
        | Command::Transform(_)
        | Command::Statistics(_)
        | Command::WidthScan(_)
        | Command::Feasibility(_) => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_commands_have_explicit_or_default_paths() {
        for (args, expected) in [
            (vec!["--help"], Command::Help),
            (vec!["-h"], Command::Help),
            (
                vec!["validate"],
                Command::Validate("evidence/k4.json".into()),
            ),
            (
                vec!["diagnose", "input.json"],
                Command::Diagnose("input.json".into()),
            ),
            (vec!["primers"], Command::Primers("evidence/k4.json".into())),
            (
                vec!["primers", "input.json"],
                Command::Primers("input.json".into()),
            ),
        ] {
            assert_eq!(
                parse(args.into_iter().map(OsString::from)).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn invalid_commands_and_extra_arguments_are_rejected() {
        for args in [
            vec![],
            vec!["search"],
            vec!["--help", "x"],
            vec!["diagnose", "a", "b"],
        ] {
            assert!(parse(args.into_iter().map(OsString::from)).is_err());
        }
    }

    #[test]
    fn help_explains_scope_without_reading_evidence() {
        let mut output = Vec::new();
        run([OsString::from("--help")], &mut output).unwrap();
        assert!(
            String::from_utf8(output)
                .unwrap()
                .contains("do not recover plaintext")
        );
    }

    #[test]
    fn output_errors_are_propagated() {
        struct FailingWriter;
        impl Write for FailingWriter {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        assert!(run([OsString::from("--help")], &mut FailingWriter).is_err());
    }
}
