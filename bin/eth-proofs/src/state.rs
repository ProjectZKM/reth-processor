//! Restart-safe state for a single, machine-pinned EthProofs stream.
use eyre::{bail, Context};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::Mutex,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Identity {
    pub namespace: String,
    pub tenant: String,
    pub chain_id: u64,
    pub cluster_id: u64,
    pub elf_id: String,
    pub interval: u64,
    pub residue: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Checkpoint {
    version: u32,
    identity: Identity,
    next_block: Option<u64>,
    last_proved: Option<u64>,
}
#[derive(Debug, Serialize, Deserialize)]
struct Committed {
    block: u64,
    proof_hash: String,
    public_values_hash: String,
    report: Value,
}
pub struct State {
    root: PathBuf,
    _lock: File,
    checkpoint: Mutex<Checkpoint>,
    report_ready: tokio::sync::Notify,
}
impl State {
    pub fn open(root: &Path, identity: Identity, start: Option<u64>) -> eyre::Result<Self> {
        if identity.interval == 0 || identity.residue >= identity.interval {
            bail!("invalid block interval or residue");
        }
        if start.is_some_and(|n| n % identity.interval != identity.residue) {
            bail!("start block does not belong to this stream's residue");
        }
        fs::create_dir_all(root)?;
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(root.join("worker.lock"))?;
        lock.try_lock_exclusive().wrap_err("another worker owns this storage root")?;
        for name in ["inputs", "outputs", "outbox", "reported"] {
            fs::create_dir_all(root.join(name))?;
        }
        let path = root.join("checkpoint.json");
        let checkpoint = if path.exists() {
            let checkpoint: Checkpoint = serde_json::from_slice(&fs::read(path)?)?;
            if checkpoint.version != 1 || checkpoint.identity != identity {
                bail!("worker state identity differs from configured chain, cluster, program or stream");
            }
            checkpoint
        } else {
            Checkpoint { version: 1, identity, next_block: start, last_proved: None }
        };
        let state = Self {
            root: fs::canonicalize(root)?,
            _lock: lock,
            checkpoint: Mutex::new(checkpoint),
            report_ready: tokio::sync::Notify::new(),
        };
        state.save_checkpoint()?;
        state.recover_reports()?;
        Ok(state)
    }
    fn save_checkpoint(&self) -> eyre::Result<()> {
        atomic_write(
            &self.root.join("checkpoint.json"),
            &serde_json::to_vec(&*self.checkpoint.lock().unwrap())?,
        )
    }
    pub fn next_block(&self) -> Option<u64> {
        self.checkpoint.lock().unwrap().next_block
    }
    pub fn initialize(&self, block: u64) -> eyre::Result<()> {
        {
            let mut c = self.checkpoint.lock().unwrap();
            if c.next_block.is_none() {
                c.next_block = Some(block);
            }
        }
        self.save_checkpoint()
    }
    pub fn advance(&self, block: u64, proved: bool) -> eyre::Result<()> {
        {
            let mut c = self.checkpoint.lock().unwrap();
            if c.next_block != Some(block) {
                bail!("refusing to advance out of order");
            }
            c.next_block = Some(
                block
                    .checked_add(c.identity.interval)
                    .ok_or_else(|| eyre::eyre!("block cursor overflow"))?,
            );
            if proved {
                c.last_proved = Some(block);
            }
        }
        self.save_checkpoint()?;
        let input = self.root.join("inputs").join(format!("{block}.bin"));
        if input.exists() {
            fs::remove_file(input)?;
        }
        let hash = self.root.join("inputs").join(format!("{block}.sha256"));
        if hash.exists() {
            fs::remove_file(hash)?;
        }
        sync_dir(&self.root.join("inputs"))?;
        Ok(())
    }

    /// Skip unproved input backlog without changing completed outputs or reports.
    pub fn skip_to(&self, block: u64) -> eyre::Result<()> {
        {
            let mut c = self.checkpoint.lock().unwrap();
            let next = c.next_block.ok_or_else(|| eyre::eyre!("cursor is not initialized"))?;
            if block < next || block % c.identity.interval != c.identity.residue {
                bail!("refusing to skip backwards or outside the selected residue");
            }
            c.next_block = Some(block);
        }
        self.save_checkpoint()?;
        for entry in fs::read_dir(self.root.join("inputs"))? {
            let path = entry?.path();
            if path
                .file_stem()
                .and_then(|s| s.to_str())
                .and_then(|s| s.parse::<u64>().ok())
                .is_some_and(|number| number < block)
            {
                fs::remove_file(path)?;
            }
        }
        sync_dir(&self.root.join("inputs"))
    }
    pub fn input(&self, block: u64) -> eyre::Result<Option<Vec<u8>>> {
        let p = self.root.join("inputs").join(format!("{block}.bin"));
        if !p.exists() {
            return Ok(None);
        }
        let bytes = fs::read(p)?;
        let hash = fs::read_to_string(self.root.join("inputs").join(format!("{block}.sha256")))?;
        if digest(&bytes) != hash {
            bail!("prepared input checksum mismatch");
        }
        Ok(Some(bytes))
    }
    pub fn save_input(&self, block: u64, bytes: &[u8]) -> eyre::Result<()> {
        // A partial write can always be prepared again; the binary is published last.
        atomic_write(
            &self.root.join("inputs").join(format!("{block}.sha256")),
            digest(bytes).as_bytes(),
        )?;
        atomic_write(&self.root.join("inputs").join(format!("{block}.bin")), bytes)
    }
    pub fn commit(
        &self,
        block: u64,
        proof: &[u8],
        public_values: &[u8],
        report: Value,
    ) -> eyre::Result<()> {
        let dir = self.root.join("outputs").join(block.to_string());
        fs::create_dir_all(&dir)?;
        sync_dir(&self.root.join("outputs"))?;
        atomic_write(&dir.join("proof.bin"), proof)?;
        atomic_write(&dir.join("public_values.bin"), public_values)?;
        let committed = Committed {
            block,
            proof_hash: digest(proof),
            public_values_hash: digest(public_values),
            report,
        };
        atomic_write(&dir.join("manifest.json"), &serde_json::to_vec(&committed)?)?;
        self.ensure_report(&committed)?;
        self.report_ready.notify_one();
        Ok(())
    }
    pub fn is_committed(&self, block: u64) -> eyre::Result<bool> {
        let dir = self.root.join("outputs").join(block.to_string());
        if !dir.join("manifest.json").exists() {
            return Ok(false);
        }
        let m: Committed = serde_json::from_slice(&fs::read(dir.join("manifest.json"))?)?;
        if m.block != block ||
            digest(&fs::read(dir.join("proof.bin"))?) != m.proof_hash ||
            digest(&fs::read(dir.join("public_values.bin"))?) != m.public_values_hash
        {
            bail!("committed output checksum mismatch");
        }
        self.ensure_report(&m)?;
        Ok(true)
    }
    fn ensure_report(&self, m: &Committed) -> eyre::Result<()> {
        if !self.root.join("reported").join(format!("{}.json", m.block)).exists() {
            let path = self.root.join("outbox").join(format!("{}.json", m.block));
            if !path.exists() {
                atomic_write(&path, &serde_json::to_vec(&m.report)?)?;
            }
        }
        Ok(())
    }
    fn recover_reports(&self) -> eyre::Result<()> {
        // Only the current block can be committed before its outbox/cursor write.
        // Earlier blocks advanced only after both were persisted.
        if let Some(block) = self.next_block() {
            self.is_committed(block)?;
        }
        Ok(())
    }
    pub fn discard_inputs_from(&self, block: u64) -> eyre::Result<()> {
        for entry in fs::read_dir(self.root.join("inputs"))? {
            let path = entry?.path();
            if path
                .file_stem()
                .and_then(|s| s.to_str())
                .and_then(|s| s.parse::<u64>().ok())
                .is_some_and(|n| n >= block)
            {
                fs::remove_file(path)?;
            }
        }
        sync_dir(&self.root.join("inputs"))
    }
    pub async fn report_ready(&self) {
        self.report_ready.notified().await;
    }
    pub fn pending_count(&self) -> eyre::Result<usize> {
        Ok(fs::read_dir(self.root.join("outbox"))?
            .filter_map(Result::ok)
            .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("json"))
            .count())
    }
    pub fn pending(&self) -> eyre::Result<Vec<(u64, Value)>> {
        let mut blocks = Vec::new();
        for entry in fs::read_dir(self.root.join("outbox"))? {
            let path = entry?.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            blocks.push(path.file_stem().unwrap().to_str().unwrap().parse::<u64>()?);
        }
        blocks.sort_unstable();
        let mut pending = Vec::new();
        // Load one proof at a time so an API outage cannot inflate reporter memory.
        if let Some(block) = blocks.first() {
            pending.push((
                *block,
                serde_json::from_slice(&fs::read(
                    self.root.join("outbox").join(format!("{block}.json")),
                )?)?,
            ));
        }
        Ok(pending)
    }
    pub fn acknowledge(&self, block: u64) -> eyre::Result<()> {
        let source = self.root.join("outbox").join(format!("{block}.json"));
        if source.exists() {
            fs::rename(source, self.root.join("reported").join(format!("{block}.json")))?;
            sync_dir(&self.root.join("reported"))?;
            sync_dir(&self.root.join("outbox"))?;
        }
        Ok(())
    }
}
pub fn atomic_write(path: &Path, bytes: &[u8]) -> eyre::Result<()> {
    let temp = path.with_extension("tmp");
    let mut file = OpenOptions::new().create(true).truncate(true).write(true).open(&temp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&temp, path)?;
    sync_dir(path.parent().unwrap())
}
fn sync_dir(path: &Path) -> eyre::Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}
fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn identity() -> Identity {
        Identity {
            namespace: "test".into(),
            tenant: "ethproofs".into(),
            chain_id: 1,
            cluster_id: 8,
            elf_id: "abc".into(),
            interval: 1,
            residue: 0,
        }
    }
    #[test]
    fn skip_preserves_completed_proofs_reports_and_restart_cursor() {
        let root = tempfile::tempdir().unwrap();
        let state = State::open(root.path(), identity(), Some(10)).unwrap();
        state.commit(10, b"proof", b"values", serde_json::json!({"block_number":10})).unwrap();
        state.advance(10, true).unwrap();
        state.save_input(11, b"stale").unwrap();
        state.save_input(20, b"latest").unwrap();
        state.skip_to(20).unwrap();
        assert!(state.input(11).unwrap().is_none());
        assert_eq!(state.input(20).unwrap().unwrap(), b"latest");
        assert!(state.is_committed(10).unwrap());
        assert_eq!(state.pending_count().unwrap(), 1);
        assert!(state.skip_to(19).is_err());
        drop(state);
        let state = State::open(root.path(), identity(), None).unwrap();
        assert_eq!(state.next_block(), Some(20));
        assert_eq!(state.checkpoint.lock().unwrap().last_proved, Some(10));
        assert_eq!(state.pending_count().unwrap(), 1);
    }

    #[test]
    fn skip_rejects_a_block_outside_the_stream_residue() {
        let root = tempfile::tempdir().unwrap();
        let mut scope = identity();
        scope.interval = 2;
        scope.residue = 1;
        let state = State::open(root.path(), scope, Some(11)).unwrap();
        assert!(state.skip_to(20).is_err());
        assert_eq!(state.next_block(), Some(11));
    }
    #[test]
    fn restart_recovers_proof_and_pending_report_without_reproving() {
        let root = tempfile::tempdir().unwrap();
        let state = State::open(root.path(), identity(), Some(10)).unwrap();
        state.save_input(10, b"input").unwrap();
        state.commit(10, b"proof", b"values", serde_json::json!({"block_number":10})).unwrap();
        // Simulate the window after output commit, before cursor advancement.
        fs::remove_file(root.path().join("outbox/10.json")).unwrap();
        drop(state);
        let state = State::open(root.path(), identity(), None).unwrap();
        assert!(state.is_committed(10).unwrap());
        assert_eq!(state.pending().unwrap().len(), 1);
        state.advance(10, true).unwrap();
        state.acknowledge(10).unwrap();
        drop(state);
        let state = State::open(root.path(), identity(), None).unwrap();
        assert_eq!(state.next_block(), Some(11));
        assert!(state.pending().unwrap().is_empty());
        assert!(state.input(10).unwrap().is_none());
    }
    #[test]
    fn duplicate_owner_and_changed_program_are_rejected() {
        let root = tempfile::tempdir().unwrap();
        let state = State::open(root.path(), identity(), Some(10)).unwrap();
        assert!(State::open(root.path(), identity(), None).is_err());
        drop(state);
        let mut changed = identity();
        changed.elf_id = "other".into();
        assert!(State::open(root.path(), changed, None).is_err());
    }
    #[test]
    fn corrupted_input_or_output_is_not_reused() {
        let root = tempfile::tempdir().unwrap();
        let state = State::open(root.path(), identity(), Some(10)).unwrap();
        state.save_input(10, b"input").unwrap();
        fs::write(root.path().join("inputs/10.bin"), b"bad").unwrap();
        assert!(state.input(10).is_err());
        state.commit(10, b"proof", b"values", Value::Null).unwrap();
        fs::write(root.path().join("outputs/10/proof.bin"), b"bad").unwrap();
        assert!(state.is_committed(10).is_err());
        assert!(state.advance(11, true).is_err());
    }

    #[test]
    fn restart_preserves_prefetch_and_reorg_discards_all_future_inputs() {
        let root = tempfile::tempdir().unwrap();
        let state = State::open(root.path(), identity(), Some(10)).unwrap();
        for block in 10..14 {
            state.save_input(block, &[block as u8]).unwrap();
        }
        state.commit(10, b"proof", b"values", serde_json::json!({"block_number":10})).unwrap();
        state.advance(10, true).unwrap();
        drop(state);
        let state = State::open(root.path(), identity(), None).unwrap();
        assert_eq!(state.next_block(), Some(11));
        for block in 11..14 {
            assert_eq!(state.input(block).unwrap().unwrap(), [block as u8]);
        }
        state.discard_inputs_from(11).unwrap();
        assert_eq!(state.next_block(), Some(11));
        for block in 11..14 {
            assert!(state.input(block).unwrap().is_none());
        }
        assert!(state.is_committed(10).unwrap());
        assert_eq!(state.pending_count().unwrap(), 1);
    }
}
