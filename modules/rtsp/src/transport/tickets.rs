use super::TransportResult;
use amaterasu_gamestream::crypto::{Direction, RtspOpener, RtspSealer};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

const MAX_TICKETS: usize = 2;
const MAX_TICKET_HISTORY: usize = 128;

struct Ticket {
    peer: IpAddr,
    opener: RtspOpener,
    sealer: RtspSealer,
}

#[derive(Default)]
pub(super) struct Tickets {
    active: BTreeMap<u64, Ticket>,
    used_ids: BTreeSet<u64>,
    used_keys: Vec<[u8; 16]>,
}

impl Tickets {
    pub(super) fn add(&mut self, id: u64, peer: IpAddr, key: &[u8; 16]) -> TransportResult<()> {
        if id == 0 || self.used_ids.contains(&id) {
            return Err("ticket_id_reused");
        }
        if self.active.len() >= MAX_TICKETS {
            return Err("ticket_limit");
        }
        if self.used_ids.len() >= MAX_TICKET_HISTORY {
            return Err("ticket_history_limit");
        }
        if self.used_keys.contains(key) {
            return Err("ticket_key_reused");
        }
        let opener =
            RtspOpener::new(key, Direction::ClientToHost).map_err(|_| "ticket_crypto_failed")?;
        let sealer =
            RtspSealer::new(key, Direction::HostToClient).map_err(|_| "ticket_crypto_failed")?;
        self.active.insert(
            id,
            Ticket {
                peer,
                opener,
                sealer,
            },
        );
        self.used_ids.insert(id);
        self.used_keys.push(*key);
        Ok(())
    }

    pub(super) fn has_peer(&self, peer: IpAddr) -> bool {
        self.active.values().any(|ticket| ticket.peer == peer)
    }

    pub(super) fn remove(&mut self, id: u64) {
        self.active.remove(&id);
    }

    pub(super) fn authenticate(
        &mut self,
        peer: IpAddr,
        envelope: &[u8],
    ) -> TransportResult<(u64, Vec<u8>)> {
        // At most two active tickets are tested. Failed authentication leaves each
        // opener unchanged; only a verified message consumes its ticket sequence.
        for (&id, ticket) in self
            .active
            .iter_mut()
            .filter(|(_, ticket)| ticket.peer == peer)
        {
            if let Ok(message) = ticket.opener.open(envelope) {
                return Ok((id, message.plaintext));
            }
        }
        Err("request_authentication_failed")
    }

    pub(super) fn seal(&mut self, id: u64, plaintext: &[u8]) -> TransportResult<Vec<u8>> {
        self.active
            .get_mut(&id)
            .ok_or("ticket_not_found")?
            .sealer
            .seal(plaintext)
            .map_err(|_| "response_encryption_failed")
    }
}
