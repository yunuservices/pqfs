use std::path::Path;

use anyhow::{Result, bail};

use crate::cli::{KeygenArgs, PasswdArgs, RevokeArgs, ShareArgs, VolumeArgs, prompt_password};
use crate::crypto::{Crypto, Identity, KeySlot, PublicIdentity, volume};

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

pub fn passwd(mut args: PasswdArgs) -> Result<()> {
    args.credential.resolve()?;
    let identity = args.credential.identity_file()?;
    let mut header = volume::read_header(&args.backend)?;
    let master_key = volume::open_master_key(&header, &args.credential.unlock(&identity)?)?;

    let new_password = prompt_password("New volume password: ")?;
    if new_password != prompt_password("Repeat new password: ")? {
        bail!("the passwords do not match");
    }
    if new_password.is_empty() {
        bail!("the password must not be empty");
    }

    let kdf = header
        .slots
        .iter()
        .find_map(|slot| match slot {
            KeySlot::Password { kdf, .. } => Some(*kdf),
            _ => None,
        })
        .unwrap_or_default();

    let slot = volume::password_slot(&new_password, &header.volume_id, master_key.as_slice(), kdf)?;

    match header
        .slots
        .iter()
        .position(|slot| matches!(slot, KeySlot::Password { .. }))
    {
        Some(index) => header.slots[index] = slot,
        None => header.slots.push(slot),
    }
    volume::write_header(&args.backend, &mut header, master_key.as_slice())?;

    println!("password slot rewrapped");
    Ok(())
}

pub fn rekey(mut args: PasswdArgs) -> Result<()> {
    args.credential.resolve()?;
    let identity = args.credential.identity_file()?;
    let old = Crypto::unlock(&args.backend, args.credential.unlock(&identity)?)?;

    let mut header = volume::read_header(&args.backend)?;
    let new_master_key = volume::random_master_key();

    let mut slots = Vec::with_capacity(header.slots.len());
    for (index, slot) in header.slots.iter().enumerate() {
        slots.push(match slot {
            KeySlot::Password { kdf, .. } => {
                let password = args.credential.require_password().map_err(|_| {
                    anyhow::anyhow!(
                        "slot {index} is a password slot; pass --password so it can be rewrapped"
                    )
                })?;
                volume::password_slot(password, &header.volume_id, new_master_key.as_slice(), *kdf)?
            }
            KeySlot::Recipient {
                label,
                kem_param,
                kem_public_key,
                ..
            } => volume::recipient_slot(
                &PublicIdentity {
                    kem_param: *kem_param,
                    kem_public_key: kem_public_key.clone(),
                },
                label,
                &header.volume_id,
                new_master_key.as_slice(),
            )?,
        });
    }
    header.slots = slots;

    let new = Crypto::from_master_key(new_master_key.as_slice(), header.clone())?;
    let index = crate::fs::rekey_index(&args.backend, &old, &new)?;
    volume::commit_rekey(
        &args.backend,
        &mut header,
        new_master_key.as_slice(),
        &index,
    )?;

    println!(
        "master key retired; {} slot(s) rewrapped",
        header.slots.len()
    );
    Ok(())
}

fn public_path(private: &Path) -> std::path::PathBuf {
    let mut name = private.as_os_str().to_os_string();
    name.push(".pub");
    std::path::PathBuf::from(name)
}
