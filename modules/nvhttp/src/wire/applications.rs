//! Collect one catalog revision completely before publishing a Moonlight app list.
use super::{Call, Job, Purpose, Reply, Router, xml};
use crate::launch::DESKTOP_APP_ID;
use serde::Deserialize;
use serde_json::{Value, json};
use std::time::{Duration, Instant};

pub(super) const CATALOG_SERVICE: &str = "amaterasu.catalog/1";
const PAGE_SIZE: usize = 32;
const MAX_ENTRIES: usize = 16_384;
const MAX_PAGES: usize = 1_024;
const MAX_XML_BYTES: usize = 1024 * 1024 - 1024;
const MAX_ACTIVE_LISTS: usize = 4;
const LIST_TIMEOUT: Duration = Duration::from_secs(30);
const PREFIX: &str =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?><root status_code=\"200\" status_message=\"OK\">";
const SUFFIX: &str = "</root>";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    id: String,
    name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Page {
    ok: bool,
    revision: u64,
    entries: Vec<Entry>,
    next_cursor: Option<Cursor>,
}

#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    revision: u64,
    after: String,
    query: String,
}

pub(super) struct Applications {
    revision: Option<u64>,
    last_id: Option<u32>,
    entries: usize,
    pages: usize,
    desktop_enabled: bool,
    body: String,
}

impl Applications {
    pub fn new(desktop_enabled: bool) -> Self {
        Self {
            revision: None,
            last_id: None,
            entries: 0,
            pages: 0,
            desktop_enabled,
            body: PREFIX.into(),
        }
    }

    fn accept(&mut self, payload: Value) -> Result<Option<Cursor>, Reply> {
        let page = decode_page(payload)?;
        if self
            .revision
            .is_some_and(|revision| revision != page.revision)
        {
            return Err(xml::error(
                409,
                "catalog revision changed; request the list again",
            ));
        }
        self.revision = Some(page.revision);
        self.pages += 1;
        if self.pages > MAX_PAGES || page.entries.len() > PAGE_SIZE {
            return Err(xml::error(413, "catalog pagination limit exceeded"));
        }
        if page.entries.is_empty() && page.next_cursor.is_some() {
            return Err(xml::error(
                502,
                "catalog returned a cursor without advancing entries",
            ));
        }
        for entry in page.entries {
            self.append(entry)?;
        }
        if let Some(cursor) = &page.next_cursor {
            if cursor.revision != page.revision
                || !cursor.query.is_empty()
                || numeric_id(&cursor.after).ok() != self.last_id
            {
                return Err(xml::error(
                    502,
                    "catalog continuation cursor is inconsistent",
                ));
            }
            if self.pages == MAX_PAGES || self.entries == MAX_ENTRIES {
                return Err(xml::error(413, "catalog list exceeds pagination bounds"));
            }
        }
        Ok(page.next_cursor)
    }

    fn append(&mut self, entry: Entry) -> Result<(), Reply> {
        let id = numeric_id(&entry.id).map_err(|message| xml::error(502, message))?;
        if self.desktop_enabled && id == DESKTOP_APP_ID {
            return Err(xml::error(
                502,
                "catalog ID conflicts with the Desktop app ID",
            ));
        }
        if self.last_id.is_some_and(|previous| id <= previous) {
            return Err(xml::error(502, "catalog IDs are duplicated or not ordered"));
        }
        if entry.name.is_empty()
            || entry.name.len() > 160
            || entry.name.trim().is_empty()
            || entry.name.chars().any(char::is_control)
        {
            return Err(xml::error(502, "catalog application name is invalid"));
        }
        let entry_xml = format!(
            "<App><AppTitle>{}</AppTitle><ID>{id}</ID><IsHdrSupported>0</IsHdrSupported></App>",
            xml::escape(&entry.name)
        );
        let desktop_bytes = if self.desktop_enabled {
            format!("<App><AppTitle>Desktop</AppTitle><ID>{DESKTOP_APP_ID}</ID><IsHdrSupported>0</IsHdrSupported></App>").len()
        } else {
            0
        };
        if self.entries >= MAX_ENTRIES
            || self.body.len() + entry_xml.len() + desktop_bytes + SUFFIX.len() > MAX_XML_BYTES
        {
            return Err(xml::error(
                413,
                "catalog list exceeds the Moonlight reply limit",
            ));
        }
        self.body.push_str(&entry_xml);
        self.entries += 1;
        self.last_id = Some(id);
        Ok(())
    }

    fn finish(mut self) -> Reply {
        if self.desktop_enabled {
            self.body.push_str(&desktop_xml());
        }
        self.body.push_str(SUFFIX);
        Reply {
            status: 200,
            content_type: "application/xml; charset=utf-8",
            body: self.body.into_bytes(),
            requires_paired_tls: true,
        }
    }
}

fn desktop_xml() -> String {
    format!(
        "<App><AppTitle>Desktop</AppTitle><ID>{DESKTOP_APP_ID}</ID><IsHdrSupported>0</IsHdrSupported></App>"
    )
}

fn decode_page(payload: Value) -> Result<Page, Reply> {
    if payload["ok"] != true {
        let changed = payload["error"]["code"] == "revision_conflict";
        return Err(xml::error(
            if changed { 409 } else { 503 },
            if changed {
                "catalog revision changed; request the list again"
            } else {
                "catalog export is unavailable"
            },
        ));
    }
    if payload.get("next_cursor").is_none() {
        return Err(xml::error(
            502,
            "catalog response is missing its continuation field",
        ));
    }
    let page: Page = serde_json::from_value(payload)
        .map_err(|_| xml::error(502, "catalog export response is malformed"))?;
    if !page.ok {
        return Err(xml::error(502, "catalog export response is inconsistent"));
    }
    Ok(page)
}

fn numeric_id(id: &str) -> Result<u32, &'static str> {
    let digits = id
        .strip_prefix("app-")
        .ok_or("catalog ID is not canonical")?;
    if digits.len() != 16
        || !digits
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("catalog ID is not canonical");
    }
    let value = u64::from_str_radix(digits, 16).map_err(|_| "catalog ID is invalid")?;
    if !(1..=i32::MAX as u64).contains(&value) {
        return Err("catalog ID exceeds Moonlight's positive signed integer range");
    }
    Ok(value as u32)
}

impl Router {
    pub(super) fn applications(
        &mut self,
        connection: u64,
        trusted: bool,
        now: Instant,
    ) -> Option<Reply> {
        if !trusted {
            return Some(xml::error(401, "authenticated paired TLS is required"));
        }
        if self
            .jobs
            .values()
            .filter(|job| matches!(job.purpose, Purpose::Applications { .. }))
            .count()
            >= MAX_ACTIVE_LISTS
        {
            return Some(xml::error(503, "catalog request capacity exhausted"));
        }
        self.queue(
            Some(connection),
            Purpose::Applications {
                desktop_enabled: self.launches.desktop_enabled(),
            },
            json!({"action":"export_list","limit":PAGE_SIZE}),
            now + LIST_TIMEOUT,
            now,
        )
        .err()
        .map(|message| xml::error(503, message))
    }

    pub(super) fn resolve_applications(
        &mut self,
        mut job: Job,
        result: Result<Value, String>,
        now: Instant,
        replies: &mut Vec<(u64, Reply)>,
    ) -> Option<Job> {
        let Some(mut applications) = job.applications.take() else {
            complete(
                &job,
                xml::error(500, "catalog request state is unavailable"),
                replies,
            );
            return None;
        };
        let result = match result {
            Ok(payload)
                if applications.desktop_enabled
                    && applications.pages == 0
                    && payload["ok"] == false
                    && payload["error"]["code"] != "revision_conflict" =>
            {
                complete(&job, applications.finish(), replies);
                return None;
            }
            Ok(payload) => applications.accept(payload),
            Err(_) if applications.desktop_enabled && applications.pages == 0 => {
                complete(&job, applications.finish(), replies);
                return None;
            }
            Err(_) => Err(xml::error(503, "catalog export request failed")),
        };
        match result {
            Ok(Some(cursor)) => {
                job.applications = Some(applications);
                job.call = Call::Ready {
                    payload: json!({"action":"export_list","limit":PAGE_SIZE,"cursor":cursor}),
                    not_before: now,
                };
                Some(job)
            }
            Ok(None) => {
                complete(&job, applications.finish(), replies);
                None
            }
            Err(reply) => {
                complete(&job, reply, replies);
                None
            }
        }
    }
}

fn complete(job: &Job, reply: Reply, replies: &mut Vec<(u64, Reply)>) {
    if let Some(connection) = job.connection {
        replies.push((connection, reply));
    }
}

#[cfg(test)]
mod tests;
