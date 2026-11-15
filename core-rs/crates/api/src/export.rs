//! Contact export files (CSV, TXT, Excel) and ZIP bundles.

use std::io::{Cursor, Write};

use anyhow::{Context, Result};
use axum::body::Body;
use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::response::Response;
use chrono::{Local, TimeZone};
use ferropost_store::contacts::ExportRow;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Csv,
    Txt,
    /// Go advertised this but answered "Excel format not implemented".
    Excel,
}

impl Format {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "csv" => Some(Self::Csv),
            "txt" => Some(Self::Txt),
            "excel" => Some(Self::Excel),
            _ => None,
        }
    }

    pub fn extension(self) -> &'static str {
        match self {
            Self::Csv => "csv",
            Self::Txt => "txt",
            Self::Excel => "xlsx",
        }
    }
}

const HEADERS: [&str; 4] = ["email", "attributes", "active", "create_time"];

/// Compact JSON with sorted keys, as Go's `json.Marshal` of the map wrote it.
fn compact_attributes(raw: &str) -> String {
    serde_json::from_str::<serde_json::Value>(raw)
        .ok()
        .filter(serde_json::Value::is_object)
        .map_or_else(|| "{}".to_owned(), |v| v.to_string())
}

/// Server-local `YYYY-MM-DD HH:MM:SS`, empty for 0 (Go's format).
fn created(ts: i32) -> String {
    if ts == 0 {
        return String::new();
    }
    Local
        .timestamp_opt(i64::from(ts), 0)
        .single()
        .map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_default()
}

fn fields(row: &ExportRow) -> [String; 4] {
    [
        row.email.clone(),
        compact_attributes(&row.attribs),
        row.active.to_string(),
        created(row.create_time),
    ]
}

pub fn render(rows: &[ExportRow], format: Format) -> Result<Vec<u8>> {
    match format {
        Format::Csv => {
            let mut writer = csv::Writer::from_writer(Vec::new());
            writer.write_record(HEADERS)?;
            for row in rows {
                writer.write_record(fields(row))?;
            }
            writer.into_inner().context("finish csv")
        }
        Format::Txt => Ok(rows
            .iter()
            .map(|row| fields(row).join(","))
            .collect::<Vec<_>>()
            .join("\n")
            .into_bytes()),
        Format::Excel => {
            let mut workbook = rust_xlsxwriter::Workbook::new();
            let sheet = workbook.add_worksheet();
            sheet.set_name("Contacts")?;
            for (col, header) in HEADERS.iter().enumerate() {
                sheet.write_string(0, col as u16, *header)?;
            }
            for (i, row) in rows.iter().enumerate() {
                let r = u32::try_from(i + 1).context("too many rows for one sheet")?;
                let [email, attribs, _, created] = fields(row);
                sheet.write_string(r, 0, email)?;
                sheet.write_string(r, 1, attribs)?;
                sheet.write_number(r, 2, f64::from(row.active))?;
                sheet.write_string(r, 3, created)?;
            }
            Ok(workbook.save_to_buffer()?)
        }
    }
}

/// Bundles `(name, content)` files into a ZIP archive.
pub fn zip(files: &[(String, Vec<u8>)]) -> Result<Vec<u8>> {
    let mut archive = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    for (name, content) in files {
        archive.start_file(name.as_str(), options)?;
        archive.write_all(content)?;
    }
    Ok(archive.finish()?.into_inner())
}

/// A group name usable as a file name inside the archive.
pub fn file_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_control() || "/\\:*?\"<>|".contains(c) {
                '_'
            } else {
                c
            }
        })
        .collect();
    let cleaned = cleaned.trim().trim_matches('.').to_owned();
    if cleaned.is_empty() {
        "group".to_owned()
    } else {
        cleaned
    }
}

/// `contacts_export_<YmdHis>.<ext>` in server-local time, like Go.
pub fn download_name(extension: &str) -> String {
    format!(
        "contacts_export_{}.{extension}",
        Local::now().format("%Y%m%d%H%M%S")
    )
}

/// A file download (`application/octet-stream`, as the console expects).
pub fn download(name: &str, bytes: Vec<u8>) -> Response {
    Response::builder()
        .header(CONTENT_TYPE, "application/octet-stream")
        .header(CONTENT_DISPOSITION, format!("attachment; filename={name}"))
        .body(Body::from(bytes))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(email: &str, attribs: &str, active: i32) -> ExportRow {
        ExportRow {
            email: email.into(),
            attribs: attribs.into(),
            active,
            create_time: 0,
        }
    }

    #[test]
    fn csv_matches_go_layout() {
        let rows = [
            row("a@x.com", r#"{"z": "1", "a": "x,y"}"#, 1),
            row("b@x.com", "null", 0),
        ];
        let csv = String::from_utf8(render(&rows, Format::Csv).expect("csv")).expect("utf8");
        assert_eq!(
            csv,
            "email,attributes,active,create_time\n\
             a@x.com,\"{\"\"a\"\":\"\"x,y\"\",\"\"z\"\":\"\"1\"\"}\",1,\n\
             b@x.com,{},0,\n"
        );
    }

    #[test]
    fn txt_and_excel() {
        let rows = [row("a@x.com", "{}", 1), row("b@x.com", "{}", 0)];
        let txt = String::from_utf8(render(&rows, Format::Txt).expect("txt")).expect("utf8");
        assert_eq!(txt, "a@x.com,{},1,\nb@x.com,{},0,");
        let xlsx = render(&rows, Format::Excel).expect("xlsx");
        assert_eq!(&xlsx[..2], b"PK", "xlsx is a zip container");
    }

    #[test]
    fn zip_and_names() {
        let archive = zip(&[("a.csv".into(), b"x".to_vec())]).expect("zip");
        assert_eq!(&archive[..2], b"PK");
        assert_eq!(file_name("VIP/Leads: 2026"), "VIP_Leads_ 2026");
        assert_eq!(file_name(".."), "group");
    }
}
