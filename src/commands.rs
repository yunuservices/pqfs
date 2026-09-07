use std::path::Path;

use anyhow::{Result, bail};

use crate::cli::{KeygenArgs, RevokeArgs, ShareArgs, VolumeArgs};
use crate::crypto::{Identity, PublicIdentity, volume};

pub fn keygen(args: KeygenArgs) -> Result<()> {
    if args.out.exists() {
        bail!("{} already exists", args.out.display());
    }
    let identity = Identity::generate()?;
    identity.save(&args.out)?;

    let public_path = public_path(&args.out);
    identity.public()?.save(&public_path)?;

    println!("identity written to {}", args.out.display());
    println!(
        "share {} with anyone who should hold a slot",
        public_path.display()
    );
    Ok(())
}

pub fn slots(args: VolumeArgs) -> Result<()> {
    let header = volume::read_header(&args.backend)?;
    for (index, slot) in header.slots.iter().enumerate() {
        let label = slot.label();
        if label.is_empty() {
            println!("{index}\t{}", slot.kind());
        } else {
            println!("{index}\t{}\t{label}", slot.kind());
        }
    }
    Ok(())
}

pub fn share(mut args: ShareArgs) -> Result<()> {
    args.credential.resolve()?;
    let recipient = PublicIdentity::load(&args.to)?;
    let label = args.label.clone().unwrap_or_else(|| {
        args.to
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned()
    });

    let identity = args.credential.identity_file()?;
    let mut header = volume::read_header(&args.backend)?;
    let master_key = volume::open_master_key(&header, &args.credential.unlock(&identity)?)?;

    header.slots.push(volume::recipient_slot(
        &recipient,
        &label,
        &header.volume_id,
        master_key.as_slice(),
    )?);
    volume::write_header(&args.backend, &mut header, master_key.as_slice())?;

    println!("slot {} added for {label}", header.slots.len() - 1);
    Ok(())
}

pub fn revoke(mut args: RevokeArgs) -> Result<()> {
    args.credential.resolve()?;
    let identity = args.credential.identity_file()?;
    let mut header = volume::read_header(&args.backend)?;
    let master_key = volume::open_master_key(&header, &args.credential.unlock(&identity)?)?;

    if args.slot >= header.slots.len() {
        bail!("no slot {}", args.slot);
    }
    if header.slots.len() == 1 {
        bail!("refusing to remove the only remaining slot");
    }

    let removed = header.slots.remove(args.slot);
    volume::write_header(&args.backend, &mut header, master_key.as_slice())?;

    println!("removed {} slot {}", removed.kind(), args.slot);
    Ok(())
}

fn public_path(private: &Path) -> std::path::PathBuf {
    let mut name = private.as_os_str().to_os_string();
    name.push(".pub");
    std::path::PathBuf::from(name)
}
