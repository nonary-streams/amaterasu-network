//! Retired broker requests retain their admission slot until terminal release.
use super::*;

const RETRY_INTERVAL: Duration = Duration::from_millis(100);

impl Router {
    pub(super) fn retire_request(
        &mut self,
        request: u64,
        now: Instant,
        send: &mut impl FnMut(Command) -> ModuleResult<Response>,
    ) {
        self.cancellations.insert(request, now);
        self.retry_cancellation(request, now, send);
    }

    pub(super) fn poll_cancellations(
        &mut self,
        now: Instant,
        send: &mut impl FnMut(Command) -> ModuleResult<Response>,
    ) {
        let due: Vec<_> = self
            .cancellations
            .iter()
            .filter(|(_, retry_at)| now >= **retry_at)
            .map(|(request, _)| *request)
            .collect();
        for request in due {
            self.retry_cancellation(request, now, send);
        }
    }

    fn retry_cancellation(
        &mut self,
        request: u64,
        now: Instant,
        send: &mut impl FnMut(Command) -> ModuleResult<Response>,
    ) {
        // Cancellation may have reached the broker even when its reply was lost.
        // Always inspect the result; never replay the underlying service request.
        let _ = send(Command::Cancel { request });
        let result = send(Command::TakeResult { request });
        if released(&result) {
            self.cancellations.remove(&request);
        } else {
            self.cancellations.insert(request, now + RETRY_INTERVAL);
        }
    }
}

pub(super) fn released(response: &ModuleResult<Response>) -> bool {
    // Production uses send_ephemeral: terminal responses reach us only after
    // ReleaseResult succeeds. If release fails, its error keeps this ID tracked.
    // not_found also confirms removal (including an acknowledged-but-lost release).
    matches!(response, Ok(Response::Result { .. }))
        || matches!(response, Ok(Response::Error { code, .. })
            if matches!(code.as_str(), "cancelled" | "deadline_exceeded" | "not_found"))
}
